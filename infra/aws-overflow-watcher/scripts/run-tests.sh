#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Offline unit tests plus DynamoDB Local. No AWS account and no GitHub calls.
set -eu
root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
cache=${OVERFLOW_DDB_CACHE:-/tmp/overflow-dynamodb-local}
mkdir -p "$cache"
if [ ! -f "$cache/DynamoDBLocal.jar" ]; then
  archive=$(mktemp)
  curl -fsSL -o "$archive" "https://d1ni2b6xgvw0s0.cloudfront.net/v2.x/dynamodb_local_latest.tar.gz"
  tar -xzf "$archive" -C "$cache"
  rm -f "$archive"
fi
if ! python3 -c 'import socket; socket.create_connection(("localhost", 8000), 1).close()' 2>/dev/null; then
  java -Djava.library.path="$cache/DynamoDBLocal_lib" -jar "$cache/DynamoDBLocal.jar" -inMemory -sharedDb -port 8000 >/tmp/overflow-ddb.log 2>&1 &
  tries=0
  while [ "$tries" -lt 50 ]; do
    if python3 -c 'import socket; socket.create_connection(("localhost", 8000), 1).close()' 2>/dev/null; then
      break
    fi
    tries=$((tries + 1))
    sleep 1
  done
fi
venv=${OVERFLOW_TEST_VENV:-/tmp/overflow-watcher-venv}
if [ ! -x "$venv/bin/python" ]; then
  python3 -m venv "$venv"
fi
"$venv/bin/python" -m pip install -q -r "$root/requirements.txt"
export DDB_LOCAL_ENDPOINT="${DDB_LOCAL_ENDPOINT:-http://localhost:8000}"
export AWS_ACCESS_KEY_ID=local
export AWS_SECRET_ACCESS_KEY=local
export AWS_DEFAULT_REGION=us-west-2
export PYTHONPATH="$root/src${PYTHONPATH:+:$PYTHONPATH}"
cd "$root"
"$venv/bin/python" -m unittest discover -s tests -v
