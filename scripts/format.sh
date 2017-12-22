#!/bin/bash

set -eo pipefail

set -x

DIR="${BASH_SOURCE%/*}"
if [[ ! -d "$DIR" ]]; then DIR="$PWD"; fi

cd "${DIR}"
cd ..

clang-format -style=file -i *.c