#!/bin/bash

export NOTARY_PORT=9994

docker build -t sebbyii/signy-wrapper:0.1.1 .
docker push sebbyii/signy-wrapper:0.1.1
#docker run -v /var/run/docker.sock:/var/run/docker.sock -p 4445:4445 sebbyii/signy-wrapper:0.0.3
docker run --privileged -p 4445:4445 sebbyii/signy-wrapper:0.1.1
