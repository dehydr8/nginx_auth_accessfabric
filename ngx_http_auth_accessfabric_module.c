/**
 *  Copyright 2017, ScaleFT Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <pthread.h>

#include <curl/curl.h>

#include "xjwt/xjwt.h"

/* TODO(pquerna): more portable random: but only used to randomize the refresh
 * period */
#ifdef __linux__
#include <linux/random.h>
#else
#include <sys/random.h>
#endif

static ngx_str_t af_default_issuer = ngx_string("https://app.scaleft.com");
static ngx_str_t af_default_header = ngx_string("Authenticated-User-JWT");

static ngx_str_t af_var_sub = ngx_string("auth_accessfabric_sub");
static ngx_str_t af_var_email = ngx_string("auth_accessfabric_email");

static ngx_str_t af_jwk_default_name = ngx_string("scaleft");
static ngx_str_t af_jwk_default_url =
    ngx_string("https://app.scaleft.com/v1/oauth/access_fabric_certs");

typedef struct {
  xjwt_keyset_t *keyset;
  uint32_t generation;
} af_keyset_t;

typedef struct {
  ngx_str_t url;

  /* mtx protects the vars bellow as they are mutated by both nginx worker
   * threads and our updating thread */
  pthread_mutex_t mtx;
  const char *jwk_data;
  size_t jwk_len;
  uint32_t active_generation;
  /* array of *af_keyset_t */
  ngx_array_t *keysets;

  ngx_log_t *log;
  ngx_pool_t *pool;
  pthread_t thread;
  int exiting;
  pthread_cond_t cond;
  struct timespec nextrefresh;
} af_jwk_refresher_t;

static ngx_int_t af_jwk_create(ngx_conf_t *cf, ngx_str_t *url,
                               af_jwk_refresher_t **out);
static ngx_int_t af_jwk_init_worker(ngx_cycle_t *cycle, af_jwk_refresher_t *jr);
static void *af_jwk__thread_run(void *data);
static ngx_int_t af_jwk__thread_main(af_jwk_refresher_t *jr);
static void af_jwk_exit_worker(ngx_cycle_t *cycle, af_jwk_refresher_t *jr);
static void af_jwk__refresh(af_jwk_refresher_t *jr);

static ngx_int_t af_jwk_get(af_jwk_refresher_t *jr, af_keyset_t **keyset);
static void af_jwk_release(af_jwk_refresher_t *jr, af_keyset_t *keyset);

typedef struct {
  ngx_str_t key;
  af_jwk_refresher_t *jwks;
} af_keyjwk_t;

typedef struct {
  ngx_flag_t enabled;
  ngx_str_t audience;
  ngx_str_t issuer;
  ngx_str_t header;
  ngx_str_t trusted_jwks;
} ngx_http_auth_accessfabric_loc_conf_t;

typedef struct {
  /* array of ngx_keyval_t */
  ngx_array_t *cache_jwks;
  /* array of af_keyjwk_t */
  ngx_array_t *jwks;
} ngx_http_auth_accessfabric_main_conf_t;

extern ngx_module_t ngx_http_auth_accessfabric_module;

static void *ngx_http_auth_accessfabric_create_main_conf(ngx_conf_t *cf) {
  ngx_http_auth_accessfabric_main_conf_t *mainconf;

  mainconf = ngx_pcalloc(cf->pool, sizeof(*mainconf));
  if (!mainconf) {
    return NULL;
  }

  return mainconf;
}

static void *ngx_http_auth_accessfabric_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_auth_accessfabric_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(*conf));
  if (!conf) {
    return NULL;
  }

  conf->enabled = NGX_CONF_UNSET;

  return conf;
}

static char *ngx_http_auth_accessfabric_merge_loc_conf(ngx_conf_t *cf,
                                                       void *parent,
                                                       void *child) {
  ngx_http_auth_accessfabric_loc_conf_t *prev = parent;
  ngx_http_auth_accessfabric_loc_conf_t *conf = child;

  ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

  ngx_conf_merge_str_value(conf->audience, prev->audience, "");
  ngx_conf_merge_str_value(conf->issuer, prev->issuer, "");
  ngx_conf_merge_str_value(conf->header, prev->header, "");
  ngx_conf_merge_str_value(conf->trusted_jwks, prev->trusted_jwks, "");

  return NGX_CONF_OK;
}

/**
 * Based on:
 * https://www.nginx.com/resources/wiki/start/topics/examples/headers_management/
 */
static ngx_table_elt_t *search_headers_in(ngx_http_request_t *r, u_char *name,
                                          size_t len) {
  ngx_list_part_t *part;
  ngx_table_elt_t *h;
  ngx_uint_t i;

  /*
  Get the first part of the list. There is usual only one part.
  */
  part = &r->headers_in.headers.part;
  h = part->elts;

  /*
  Headers list array may consist of more than one part,
  so loop through all of it
  */
  for (i = 0; /* void */; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        /* The last part, search is done. */
        break;
      }

      part = part->next;
      h = part->elts;
      i = 0;
    }

    /*
    Just compare the lengths and then the names case insensitively.
    */
    if (len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0) {
      /* This header doesn't match. */
      continue;
    }

    /*
    Ta-da, we got one!
    Note, we'v stop the search at the first matched header
    while more then one header may fit.
    */
    return &h[i];
  }

  /*
  No headers was found
  */
  return NULL;
}

static const char *auth_af_xjwt_reasonstr(XJWT_VERIFY_FAILURES r) {
  switch (r) {
    case XJWT_VERIFY_UNKNOWN:
      return "UNKNOWN";
    case XJWT_VERIFY_NOT_PRESENT:
      return "NOT_PRESENT";
    case XJWT_VERIFY_EXPIRED:
      return "EXPIRED";
    case XJWT_VERIFY_INVALID_SIGNATURE:
      return "INVALID_SIGNATURE";
    case XJWT_VERIFY_NO_VALIDATORS:
      return "NO_VALIDATORS";
    case XJWT_VERIFY_MALFORMED:
      return "MALFORMED";
    case XJWT_VERIFY_EXPECT_MISMATCH:
      return "EXPECT_MISMATCH";
  }
  return "INTERNAL_UNKNOWN";
}

typedef struct ngx_http_auth_accessfabric_req_ctx_t {
  ngx_str_t sub;
  ngx_str_t email;
} ngx_http_auth_accessfabric_req_ctx_t;

typedef struct tcb_baton_t {
  uint64_t now;
} tcb_baton_t;

static uint64_t tcb(void *baton) { return ((tcb_baton_t *)baton)->now; }

static void af_cpyjstr(ngx_pool_t *pool, json_t *input, ngx_str_t *target) {
  size_t len;
  const char *sv;
  sv = json_string_value(input);
  len = strlen(sv);
  target->data = ngx_pcalloc(pool, len + 1);
  memcpy(target->data, sv, len);
  target->len = len;
}

static ngx_int_t ngx_http_auth_accessfabric_handler(ngx_http_request_t *r) {
  ngx_table_elt_t *hdr = NULL;
  ngx_http_auth_accessfabric_loc_conf_t *cf =
      ngx_http_get_module_loc_conf(r, ngx_http_auth_accessfabric_module);
  ngx_http_auth_accessfabric_main_conf_t *mainconf =
      ngx_http_get_module_main_conf(r, ngx_http_auth_accessfabric_module);

  if (cf->enabled == NGX_CONF_UNSET || !cf->enabled) {
    return NGX_DECLINED;
  }

  if (cf->audience.len == 0) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "AuthAccessFabric: auth_accessfabric_audience must be set "
                  "when auth_accessfabric is enabled");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  if (cf->header.len == 0) {
    hdr = search_headers_in(r, af_default_header.data, af_default_header.len);
  } else {
    hdr = search_headers_in(r, cf->header.data, cf->header.len);
  }

  if (hdr == NULL) {
    if (cf->header.len == 0) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "AuthAccessFabric: Empty JWT Request Header: %V",
                    &af_default_header);
    } else {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "AuthAccessFabric: Empty JWT Request Header: %V",
                    &cf->header);
    }
    return NGX_HTTP_UNAUTHORIZED;
  }

  do {
    tcb_baton_t baton = {0};
    xjwt_verify_options_t opts;
    xjwt_verify_failure_t *failed = NULL;
    xjwt_verify_success_t *success = NULL;
    ngx_uint_t i;
    af_keyset_t *ks = NULL;
    af_jwk_refresher_t *jr = NULL;
    af_keyjwk_t *jrent;
    ngx_int_t st;
    ngx_str_t *trusted_name = &cf->trusted_jwks;
    if (trusted_name->len == 0) {
      trusted_name = &af_jwk_default_name;
    }

    for (jrent = mainconf->jwks->elts, i = 0; i < mainconf->jwks->nelts; i++) {
      af_keyjwk_t kj = jrent[i];
      if (ngx_strcasecmp(trusted_name->data, kj.key.data) == 0) {
        jr = kj.jwks;
        break;
      }
    }

    if (jr == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "AuthAccessFabric: No configured keyset available for "
                    "validation (name=%V)",
                    trusted_name);
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    st = af_jwk_get(jr, &ks);
    if (st != NGX_OK) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, st,
                    "AuthAccessFabric: Keyset fetching failed (name=%V)",
                    trusted_name);
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ks == NULL) {
      ngx_log_error(
          NGX_LOG_ERR, r->connection->log, 0,
          "AuthAccessFabric: No keyset available for validation (name=%V)",
          trusted_name);
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    opts.keyset = ks->keyset;
    if (cf->issuer.len != 0) {
      opts.expected_issuer = (const char *)cf->issuer.data;
    } else {
      opts.expected_issuer = (const char *)af_default_issuer.data;
    }
    opts.expected_subject = NULL;
    opts.expected_audience = (const char *)cf->audience.data;
    opts.now = tcb;
    opts.baton = &baton;
    /* TODO(pquerna): use nginx time funcs to get a UTC cached time */
    baton.now = time(NULL);

    xjwt_verify(&opts, (const char *)hdr->value.data, hdr->value.len, &success,
                &failed);

    af_jwk_release(jr, ks);

    if (success != NULL) {
      ngx_http_auth_accessfabric_req_ctx_t *mctx = NULL;
      json_t *sub = NULL;
      json_t *email = NULL;

      /* json_dumpf(success->payload, stderr, JSON_INDENT(2)); */
      sub = json_object_get(success->payload, "sub");
      if (!json_is_string(sub)) {
        xjwt_verify_success_destroy(success);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "AuthAccessFabric: Payload did not contain sub");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }

      email = json_object_get(success->payload, "email");
      if (!json_is_string(email)) {
        xjwt_verify_success_destroy(success);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "AuthAccessFabric: Payload did not contain email");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }

      mctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_accessfabric_req_ctx_t));
      if (mctx == NULL) {
        xjwt_verify_success_destroy(success);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "AuthAccessFabric: Failed to allocate module context");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }

      af_cpyjstr(r->pool, sub, &mctx->sub);
      af_cpyjstr(r->pool, email, &mctx->email);

      ngx_http_set_ctx(r, mctx, ngx_http_auth_accessfabric_module);

      xjwt_verify_success_destroy(success);
      return NGX_OK;
    } else {
      if (failed->err != NULL) {
        ngx_log_error(
            NGX_LOG_ERR, r->connection->log, 0,
            "AuthAccessFabric: request validation failed with '%s': (%d) %s",
            auth_af_xjwt_reasonstr(failed->reason), failed->err->err,
            failed->err->msg);
      } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "AuthAccessFabric: request validation failed with '%s'",
                      auth_af_xjwt_reasonstr(failed->reason));
      }

      xjwt_verify_failure_destroy(failed);
      return NGX_HTTP_UNAUTHORIZED;
    }
  } while (0);

  return NGX_HTTP_UNAUTHORIZED;
}

static ngx_int_t ngx_http_auth_accessfabric_init(ngx_conf_t *cf) {
  ngx_http_handler_pt *h;
  ngx_int_t rv;
  ngx_uint_t i;
  ngx_keyval_t *jwk_keys;
  ngx_keyval_t *kv;
  ngx_http_core_main_conf_t *coreconf;
  ngx_http_auth_accessfabric_main_conf_t *mainconf =
      ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_accessfabric_module);

  coreconf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&coreconf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_auth_accessfabric_handler;

  if (mainconf->cache_jwks == NULL) {
    mainconf->cache_jwks = ngx_array_create(cf->pool, 1, sizeof(ngx_keyval_t));
    kv = ngx_array_push(mainconf->cache_jwks);
    if (kv == NULL) {
      return NGX_ERROR;
    }
    kv->key = af_jwk_default_name;
    kv->value = af_jwk_default_url;
  }

  mainconf->jwks = ngx_array_create(cf->pool, mainconf->cache_jwks->nelts,
                                    sizeof(af_keyjwk_t));
  for (jwk_keys = mainconf->cache_jwks->elts, i = 0;
       i < mainconf->cache_jwks->nelts; i++) {
    af_keyjwk_t *kj;
    af_jwk_refresher_t *jr = NULL;
    rv = af_jwk_create(cf, &jwk_keys[i].value, &jr);
    if (rv != NGX_OK) {
      return rv;
    }

    kj = ngx_array_push(mainconf->jwks);
    if (kj == NULL) {
      return NGX_ERROR;
    }
    kj->jwks = jr;
    kj->key.data = jwk_keys[i].key.data;
    kj->key.len = jwk_keys[i].key.len;
  }
  return NGX_OK;
}

static ngx_int_t af_jwk_create(ngx_conf_t *cf, ngx_str_t *url,
                               af_jwk_refresher_t **out) {
  af_jwk_refresher_t *jr = calloc(1, sizeof(af_jwk_refresher_t));

  pthread_mutex_init(&jr->mtx, NULL);
  pthread_cond_init(&jr->cond, NULL);
  jr->log = cf->log;
  jr->pool = cf->pool;
  jr->url.data = ngx_pstrdup(jr->pool, url);
  jr->url.len = url->len;
  jr->keysets = ngx_array_create(jr->pool, 4, sizeof(af_keyset_t *));

  *out = jr;
  return NGX_OK;
}

static ngx_command_t ngx_http_auth_accessfabric_commands[] = {
    {ngx_string("auth_accessfabric"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_accessfabric_loc_conf_t, enabled), NULL},
    {ngx_string("auth_accessfabric_audience"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_accessfabric_loc_conf_t, audience), NULL},
    {ngx_string("auth_accessfabric_issuer"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_accessfabric_loc_conf_t, issuer), NULL},
    {ngx_string("auth_accessfabric_header"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_accessfabric_loc_conf_t, header), NULL},
    {ngx_string("auth_accessfabric_trusted_jwks"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_accessfabric_loc_conf_t, trusted_jwks), NULL},

    {ngx_string("auth_accessfabric_jwk_cache"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2, ngx_conf_set_keyval_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_auth_accessfabric_main_conf_t, cache_jwks), NULL},

    ngx_null_command};

static ngx_int_t ngx_http_auth_accessfabric_get_sub(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
  ngx_http_auth_accessfabric_req_ctx_t *mctx =
      ngx_http_get_module_ctx(r, ngx_http_auth_accessfabric_module);
  if (mctx == NULL) {
    v->not_found = 1;
    return NGX_OK;
  }

  if (mctx->sub.len == 0) {
    v->not_found = 1;
    return NGX_OK;
  }

  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;
  v->len = mctx->sub.len;
  v->data = mctx->sub.data;
  return NGX_OK;
}

static ngx_int_t ngx_http_auth_accessfabric_get_email(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
  ngx_http_auth_accessfabric_req_ctx_t *mctx =
      ngx_http_get_module_ctx(r, ngx_http_auth_accessfabric_module);
  if (mctx == NULL) {
    v->not_found = 1;
    return NGX_OK;
  }

  if (mctx->email.len == 0) {
    v->not_found = 1;
    return NGX_OK;
  }

  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;
  v->len = mctx->email.len;
  v->data = mctx->email.data;
  return NGX_OK;
}

static ngx_int_t ngx_http_auth_accessfabric_preconfig(ngx_conf_t *cf) {
  ngx_http_variable_t *var;

  var = ngx_http_add_variable(cf, &af_var_sub, 0);
  if (var == NULL) {
    return NGX_ERROR;
  }

  var->get_handler = ngx_http_auth_accessfabric_get_sub;

  var = ngx_http_add_variable(cf, &af_var_email, 0);
  if (var == NULL) {
    return NGX_ERROR;
  }

  var->get_handler = ngx_http_auth_accessfabric_get_email;

  return NGX_OK;
}

static ngx_int_t ngx_http_auth_accessfabric_init_worker(ngx_cycle_t *cycle) {
  ngx_int_t rv;
  ngx_uint_t i;
  af_keyjwk_t *jrent;
  ngx_http_auth_accessfabric_main_conf_t *mainconf;

  if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE) {
    return NGX_OK;
  }

  curl_global_init(CURL_GLOBAL_DEFAULT);

  mainconf =
      ngx_http_cycle_get_module_main_conf(cycle, ngx_http_auth_accessfabric_module);
  if (mainconf == NULL) {
    ngx_log_error(
        NGX_LOG_ALERT, cycle->log, 0,
        "AuthAccessFabric: failed to get main configuration in init_worker");
    return NGX_ERROR;
  }

  for (jrent = mainconf->jwks->elts, i = 0; i < mainconf->jwks->nelts; i++) {
    af_keyjwk_t kj = jrent[i];
    af_jwk_refresher_t *jr = kj.jwks;
    rv = af_jwk_init_worker(cycle, jr);
    if (rv != NGX_OK) {
      return rv;
    }
  }

  return NGX_OK;
}

static void ngx_http_auth_accessfabric_exit_worker(ngx_cycle_t *cycle) {
  ngx_uint_t i;
  af_keyjwk_t *jrent;
  ngx_http_auth_accessfabric_main_conf_t *mainconf;

  if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE) {
    return;
  }

  mainconf =
      ngx_http_cycle_get_module_main_conf(cycle, ngx_http_auth_accessfabric_module);
  if (mainconf == NULL) {
    ngx_log_error(
        NGX_LOG_ALERT, cycle->log, 0,
        "AuthAccessFabric: failed to get main configuration in exit_worker");
    return;
  }

  for (jrent = mainconf->jwks->elts, i = 0; i < mainconf->jwks->nelts; i++) {
    af_keyjwk_t kj = jrent[i];
    af_jwk_refresher_t *jr = kj.jwks;
    af_jwk_exit_worker(cycle, jr);
  }
  curl_global_cleanup();
}

static ngx_int_t af_jwk_init_worker(ngx_cycle_t *cycle,
                                    af_jwk_refresher_t *jr) {
  int err;
  pthread_attr_t attr;
  jr->log = cycle->log;

  /* initial run fetching the JWKs */
  af_jwk__refresh(jr);

  err = pthread_attr_init(&attr);
  if (err) {
    ngx_log_error(NGX_LOG_ALERT, jr->log, err,
                  "AuthAccessFabric: pthread_attr_init() failed");
    return NGX_ERROR;
  }

  err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  if (err) {
    ngx_log_error(NGX_LOG_ALERT, jr->log, err,
                  "AuthAccessFabric: pthread_attr_setdetachstate() failed");
    pthread_attr_destroy(&attr);
    return NGX_ERROR;
  }

  err = pthread_create(&jr->thread, &attr, af_jwk__thread_run, jr);
  if (err) {
    ngx_log_error(NGX_LOG_ALERT, jr->log, err,
                  "AuthAccessFabric: pthread_create() failed");
    pthread_attr_destroy(&attr);
    return NGX_ERROR;
  }

  pthread_attr_destroy(&attr);

  return NGX_OK;
}

static void af_jwk_exit_worker(ngx_cycle_t *cycle, af_jwk_refresher_t *jr) {
  pthread_mutex_lock(&jr->mtx);
  jr->exiting = 1;
  pthread_cond_signal(&jr->cond);
  pthread_mutex_unlock(&jr->mtx);
  pthread_join(jr->thread, NULL);
  pthread_cond_destroy(&jr->cond);
}

static void *af_jwk__thread_run(void *data) {
  int err;
  sigset_t set;
  af_jwk_refresher_t *jr = data;

  // based on the flow in ngx_thread_pool_cycle
  sigfillset(&set);
  sigdelset(&set, SIGILL);
  sigdelset(&set, SIGFPE);
  sigdelset(&set, SIGSEGV);
  sigdelset(&set, SIGBUS);

  err = pthread_sigmask(SIG_BLOCK, &set, NULL);
  if (err) {
    ngx_log_error(NGX_LOG_ALERT, jr->log, err,
                  "AuthAccessFabric: pthread_sigmask() failed");
    return NULL;
  }

  err = af_jwk__thread_main(jr);
  if (err) {
    ngx_log_error(NGX_LOG_ALERT, jr->log, err,
                  "AuthAccessFabric: af_jwk__thread_main() failed");
    return NULL;
  }

  return NULL;
}

typedef struct {
  af_jwk_refresher_t *jr;
  CURL *curl;
  char *buf;
  size_t bsize;
} af_jwk_req_t;

#define MAX_JWK_SIZE 1000000

static size_t af_jwk__req_write_func(void *data, size_t len, size_t nmemb,
                                     void *baton) {
  af_jwk_req_t *req = (af_jwk_req_t *)baton;
  size_t blen = len * nmemb;

  if (req->bsize + blen > MAX_JWK_SIZE) {
    return 0;
  }

  req->buf = realloc(req->buf, req->bsize + blen + 1);
  if (req->buf == NULL) {
    return 0;
  }

  memcpy(&(req->buf[req->bsize]), data, blen);
  req->bsize += blen;
  req->buf[req->bsize] = '\0';
  return blen;
}

static void af_jwk__req_destroy(af_jwk_req_t *req) {
  if (req->curl != NULL) {
    curl_easy_cleanup(req->curl);
    req->curl = NULL;
  }
  if (req->buf != NULL) {
    free(req->buf);
    req->buf = NULL;
  }
  free(req);
}

static af_jwk_req_t *af_jwk__req_make(af_jwk_refresher_t *jr) {
  af_jwk_req_t *req = calloc(1, sizeof(af_jwk_req_t));
  req->jr = jr;
  CURL *curl = curl_easy_init();
  /* uncomment for more debugging: */
  /* curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L); */
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "ngx_auth_accessfabric/0.1.0");
  curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(curl, CURLOPT_URL, jr->url.data);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
  curl_easy_setopt(curl, CURLOPT_MAXFILESIZE, 512000L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, af_jwk__req_write_func);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, req);
  req->curl = curl;
  return req;
}

#ifdef __linux__
static int getentropy(void *buf, size_t buflen) {
/**
 * getrandom is not available on most Linux yet, and we don't have
 * an easy autoconf for it.
 **/
#if 0
  int ret;

  if (buflen > 256) {
    goto failure;
  }

  /* TODO(pquerna): old linux */
  ret = getrandom(buf, buflen, 0);
  if (ret < 0) {
    return ret;
  }

  if (ret == buflen) {
    return 0;
  }
failure:
  errno = EIO;
  return -1;
#else
  size_t rlen;
  FILE *fp = fopen("/dev/urandom", "rb");
  if (fp == NULL) {
    return -1;
  }
  rlen = fread(buf, 1, buflen, fp);
  fclose(fp);
  if (rlen == buflen) {
    return 0;
  }
  return -1;
#endif
}
#endif

static void af_jwk__refresh(af_jwk_refresher_t *jr) {
  uint64_t random = 0;
  uint64_t min = 1000;
  uint64_t max = 1800;
  int err = 0;
  CURLcode curle;
  long response_code;
  xjwt_keyset_t *ks = NULL;
  xjwt_error_t *xerr = NULL;
  af_keyset_t *afks = NULL;
  af_keyset_t **arrks = NULL;
  ngx_array_t *oldks = NULL;

  af_jwk_req_t *req = af_jwk__req_make(jr);
  ngx_log_error(NGX_LOG_DEBUG, jr->log, 0, "AuthAccessFabric: Fetching '%V'",
                &jr->url);

  curle = curl_easy_perform(req->curl);
  if (curle != CURLE_OK) {
    ngx_log_error(NGX_LOG_ALERT, jr->log, 0,
                  "AuthAccessFabric: Error Fetching '%V': (%d) %s", &jr->url,
                  curle, curl_easy_strerror(curle));
    err = 1;
    goto cleanup;
  }

  curle = curl_easy_getinfo(req->curl, CURLINFO_RESPONSE_CODE, &response_code);
  if (curle != CURLE_OK) {
    ngx_log_error(NGX_LOG_ALERT, jr->log, 0,
                  "AuthAccessFabric: Error Reading Response Code '%V': (%d) %s",
                  &jr->url, curle, curl_easy_strerror(curle));
    err = 1;
    goto cleanup;
  }

  if (response_code != 200) {
    ngx_log_error(NGX_LOG_ALERT, jr->log, 0,
                  "AuthAccessFabric: Error Fetching '%V': HTTP Status %ld",
                  &jr->url, response_code);
    err = 1;
    goto cleanup;
  }

  xerr = xjwt_keyset_create_from_memory(req->buf, req->bsize, &ks);
  if (xerr != XJWT_SUCCESS) {
    ngx_log_error(NGX_LOG_ALERT, jr->log, 0,
                  "AuthAccessFabric: Failed to parse JWKs from '%V': (%d) %s",
                  &jr->url, xerr->err, xerr->msg);
    err = 1;
    goto cleanup;
  }

  pthread_mutex_lock(&jr->mtx);
  jr->active_generation++;
  if (jr->jwk_data != NULL) {
    free((void *)jr->jwk_data);
    jr->jwk_data = NULL;
  }
  jr->jwk_len = req->bsize;
  jr->jwk_data = calloc(1, req->bsize + 1);
  memcpy((void *)jr->jwk_data, req->buf, req->bsize);
  oldks = jr->keysets;

  jr->keysets = ngx_array_create(jr->pool, 4, sizeof(af_keyset_t *));

  arrks = (af_keyset_t **)ngx_array_push(jr->keysets);
  afks = calloc(1, sizeof(af_keyset_t));
  afks->keyset = ks;
  afks->generation = jr->active_generation;
  *arrks = afks;
  pthread_mutex_unlock(&jr->mtx);

  if (oldks != NULL) {
    ngx_uint_t i;
    for (i = 0; i < oldks->nelts; i++) {
      afks = *(((af_keyset_t ***)oldks->elts)[i]);
      xjwt_keyset_destroy(afks->keyset);
      free(afks);
    }

    ngx_array_destroy(oldks);
  }
  ngx_log_error(NGX_LOG_DEBUG, jr->log, 0,
                "AuthAccessFabric: Updated cache of '%V' (size=%zu)", &jr->url,
                req->bsize);

cleanup:
  if (err != 0) {
    min = 60;
    max = 300;
  }
  /* this is safe even if getentropy fails; */
  getentropy(&random, sizeof(uint64_t));
  jr->nextrefresh.tv_sec = time(NULL) + ((random % (max + 1 - min)) + max);
  jr->nextrefresh.tv_nsec = 0;

  if (req != NULL) {
    af_jwk__req_destroy(req);
  }
  if (xerr != NULL) {
    xjwt_error_destroy(xerr);
  }
}

static ngx_int_t af_jwk_get(af_jwk_refresher_t *jr, af_keyset_t **keyset) {
  xjwt_keyset_t *ks = NULL;
  af_keyset_t *afks = NULL;
  af_keyset_t **arrks = NULL;
  xjwt_error_t *xerr = NULL;

  pthread_mutex_lock(&jr->mtx);
  if (jr->keysets->nelts == 0) {
    if (jr->jwk_data == NULL || jr->jwk_len == 0) {
      pthread_mutex_unlock(&jr->mtx);
      ngx_log_error(NGX_LOG_ALERT, jr->log, 0,
                    "AuthAccessFabric: No validating JWKs available: %V",
                    &jr->url);
      return NGX_ERROR;
    }

    xerr = xjwt_keyset_create_from_memory(jr->jwk_data, jr->jwk_len, &ks);
    if (xerr != XJWT_SUCCESS) {
      pthread_mutex_unlock(&jr->mtx);
      ngx_log_error(NGX_LOG_ALERT, jr->log, 0,
                    "AuthAccessFabric: Failed to parse JWKs from '%V': (%d) %s",
                    &jr->url, xerr->err, xerr->msg);
      xjwt_error_destroy(xerr);
      return NGX_ERROR;
    }

    afks = calloc(1, sizeof(af_keyset_t));
    afks->keyset = ks;
    afks->generation = jr->active_generation;
    pthread_mutex_unlock(&jr->mtx);

    *keyset = afks;
    return NGX_OK;
  }

  /* remove last nelts emtry */
  arrks = (af_keyset_t **)jr->keysets->elts +
          (jr->keysets->size * (jr->keysets->nelts - 1));
  jr->keysets->nelts--;
  *keyset = *arrks;
  pthread_mutex_unlock(&jr->mtx);

  return NGX_OK;
}

static void af_jwk_release(af_jwk_refresher_t *jr, af_keyset_t *keyset) {
  af_keyset_t **arrks = NULL;

  pthread_mutex_lock(&jr->mtx);
  if (jr->active_generation != keyset->generation) {
    pthread_mutex_unlock(&jr->mtx);
    xjwt_keyset_destroy(keyset->keyset);
    free(keyset);
    return;
  }

  arrks = ngx_array_push(jr->keysets);
  *arrks = keyset;
  pthread_mutex_unlock(&jr->mtx);
}

/**
 * constraint: af_jwk__refresh() called at least once before this to initialize
 *jr->nextrefresh;
 **/
static ngx_int_t af_jwk__thread_main(af_jwk_refresher_t *jr) {
  int rv;

  do {
    pthread_mutex_lock(&jr->mtx);
    if (jr->exiting == 1) {
      pthread_mutex_unlock(&jr->mtx);
      return NGX_OK;
    }

    rv = pthread_cond_timedwait(&jr->cond, &jr->mtx, &jr->nextrefresh);
    if (rv == 0) {
      if (jr->exiting == 1) {
        pthread_mutex_unlock(&jr->mtx);
        return NGX_OK;
      }
    } else {
      if (rv == ETIMEDOUT) {
        pthread_mutex_unlock(&jr->mtx);
        af_jwk__refresh(jr);
      }
    }
  } while (1);
  return NGX_OK;
}

static ngx_http_module_t ngx_http_auth_accessfabric_module_ctx = {
    ngx_http_auth_accessfabric_preconfig,         // preconfiguration
    ngx_http_auth_accessfabric_init,              // postconfiguration
    ngx_http_auth_accessfabric_create_main_conf,  // create main configuration
    NULL,                                         // init main configuration
    NULL,                                         // create server configuration
    NULL,                                         // merge server configuration
    ngx_http_auth_accessfabric_create_loc_conf,   // create location
                                                  // configuration
    ngx_http_auth_accessfabric_merge_loc_conf  // merge location configuration
};

ngx_module_t ngx_http_auth_accessfabric_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_accessfabric_module_ctx,  // module context
    ngx_http_auth_accessfabric_commands,     // module directives
    NGX_HTTP_MODULE,                         // module type
    NULL,                                    // init master
    NULL,                                    // init module
    ngx_http_auth_accessfabric_init_worker,  // init process
    NULL,                                    // init thread
    NULL,                                    // exit thread
    ngx_http_auth_accessfabric_exit_worker,  // exit process
    NULL,                                    // exit master
    NGX_MODULE_V1_PADDING};
