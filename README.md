# nginx_auth_accessfabric

[![Build Status](https://travis-ci.org/ScaleFT/nginx_auth_accessfabric.svg?branch=master)](https://travis-ci.org/ScaleFT/nginx_auth_accessfabric)

`ngx_http_auth_accessfabric` is an Nginx module for authenticating requests from the ScaleFT Access Fabric.  Requests are authenticated by validating the contents of the `Authenticated-User-JWT` header against a list of trusted signing JWKs from the ScaleFT Platform.

# What's New

## 1.0.0

Initial open source release.

# Configuration

`ngx_http_auth_accessfabric` adds several new configuration options. When enabled, the module checks for a signed header from the ScaleFT Access Fabric in the `Authenticated-User-JWT` header.

## Minimal configuration

The `auth_accessfabric_audience` configuration option must be set to the ScaleFT Application URL.  This represents the authorization scope for a request from a user.

In the ScaleFT dashboard, you can create an Access Fabric Application under a Project. Get the `APPLICATION URL` from the ScaleFT dashboard, and replace `calm-cerberus-0352.accessfabric.com` in the example below with your `APPLICATION URL`:

```
load_module modules/ngx_http_auth_accessfabric_module.so;

http {
    server {
        // ... other standard nginx configuration above here.
        auth_accessfabric on;
        auth_accessfabric_audience "https://calm-cerberus-0352.accessfabric.com";
    }
}

```

## Registered Variables

On sucessful authentication, `ngx_http_auth_accessfabric` sets the variables `auth_accessfabric_sub` and `auth_accessfabric_email` with validated values from the JWT. 

## Dependencies

- nginx >= 1.11
- [libxjwt](https://github.com/ScaleFT/libxjwt): Library for validating JWTs
- [libcurl](https://curl.haxx.se/libcurl/): Library for fetching remote JWKs
- [OpenSSL](https://www.openssl.org/): `libxjwt` uses EC and EVP APIs.
- [Jansson](http://www.digip.org/jansson/): JSON Parser used by `libxjwt`

## Building

`ngx_http_auth_accessfabric` can be built as either a static or dynamic nginx module.  For either method,
you must first have a matching copy of the nginx source code to build the module. To build as a dynamic module:

```
git clone https://github.com/ScaleFT/nginx_auth_accessfabric.git

# Latest versions are at http://nginx.org/en/download.html
wget http://nginx.org/download/nginx-1.13.7.tar.gz
tar -xvzf nginx-1.13.7.tar.gz

cd nginx-1.13.7
./configure --add-dynamic-module=../nginx_auth_accessfabric
make
sudo make install
```

## Building from source on Centos7 (includes libxjwt rpm build and install) You may need to adjust versions.

```
sudo yum install git wget pcre-devel zlib-devel libcurl-devel jansson-devel openssl-devel redhat-rpm-config rpm-build -y
sudo yum groupinstall "Development Tools" -y
git clone https://github.com/ScaleFT/libxjwt.git
git clone https://github.com/ScaleFT/nginx_auth_accessfabric.git 
mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
rpmbuild --undefine=_disable_source_fetch -bb ./libxjwt/dist/rpm/libxjwt.spec
sudo rpm -i ./rpmbuild/RPMS/libxjwt-devel-1.0.2-1.el7.centos.x86_64.rpm
sudo rpm -i ./rpmbuild/RPMS/libxjwt-1.0.2-1.el7.centos.x86_64.rpm
wget http://nginx.org/download/nginx-1.13.7.tar.gz
tar xvzf nginx-1.13.7.tar.gz
cd nginx-1.13.7
./configure --add-dynamic-module=../nginx_auth_accessfabric --with-http_ssl_module
make
sudo make install
```

## Building an rpm for CentOS 7 using the patch for the [nginx.spec file](./dist/rpm/centos7/nginx.spec.patch)
You may need to adjust versions here and in the patch.  This is provide mainly as a template to aid in building a module rpm suitable for use with the factory nginx rpm.
This assumes you have built or aquired and installed libxjwt and libxjwt-devel via rpm. There's a spec file for building that rpm in it's repo [here.](https://github.com/ScaleFT/libxjwt/blob/master/dist/rpm/libxjwt.spec)
If you built the rpm for libjwxt, you can skip these steps and start with yumdownloader.
```
sudo yum install redhat-rpm-config rpm-build -y
mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
```
```
yumdownloader --source nginx
rpm -ivh ./nginx-1.12.2-1.el7.src.rpm
cd ~/rpmbuild/SPECS
```
Aquire the patch [file](./dist/rpm/centos7/nginx.spec.patch)
```
patch < nginx.spec.patch
rpmbuild -ba ~/rpmbuild/SPECS/nginx.spec
sudo rpm -i ~/rpmbuild/RPMS/nginx-mod-http-auth-accessfabric-1.12.2-1.el7.centos.x86_64.rpm
```

# License

`nginx_auth_accessfabric` is licensed under the Apache License Version 2.0. See the [LICENSE file](./LICENSE) for details.
