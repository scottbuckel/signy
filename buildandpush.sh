#!/bin/bash

export NOTARY_PORT=9994

docker build -t sebbyii/signy-wrapper:0.1.8 .


#docker push sebbyii/signy-wrapper:0.1.8
#docker run -v /var/run/docker.sock:/var/run/docker.sock -p 4445:4445 sebbyii/signy-wrapper:0.0.3
docker run --privileged -p 4445:4445 --add-host=notary-server-svc.notary.svc:192.168.1.211 sebbyii/signy-wrapper:0.1.8


#signy --tlscacert=/Users/scottbuckel/go/src/github.com/theupdateframework/notary/cmd/notary/root-ca.crt --server=https://localhost:4443 verify --in-toto --thick --local porter-bundle.tgz docker.io/sebbyii/test-bundle-signing:v1  --image signy-in-toto-verifier:latest