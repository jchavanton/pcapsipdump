#!/bin/sh
DIR_PREFIX=`pwd`
NAME="pcapsipdump"
IMAGE=${NAME}:latest
CONTAINER=${NAME}2

docker stop ${CONTAINER}
docker rm ${CONTAINER}
docker run -d --net=host --name=${CONTAINER} \
	-v ${PWD}/src:/src \
	-v /home/jchavanton/Downloads:/files \
	--restart unless-stopped \
	${IMAGE} \
	tail -f /dev/null
