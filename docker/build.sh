#!/bin/sh
VERSION="0.0.0"
NAME="pcapsipdump"
docker build . --no-cache -t ${NAME}
docker tag ${NAME}:latest ${NAME}:${VERSION}
