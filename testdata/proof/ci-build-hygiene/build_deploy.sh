#!/bin/bash
set -e

docker login -p $QUAY_PASSWORD quay.io
docker build --build-arg SECRET_KEY=$SECRET .
docker push quay.io/myorg/myapp:latest

GOVERSION="go1.19"
ENV_DUMP=`env`
