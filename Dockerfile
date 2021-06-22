FROM docker:dind as builder

RUN apk add --no-cache git make musl-dev go

# Configure Go
ENV GOROOT /usr/lib/go
ENV GOPATH /go
ENV PATH /go/bin:$PATH

RUN mkdir -p ${GOPATH}/src ${GOPATH}/bin


COPY . /opt/signy
WORKDIR /opt/signy/
RUN make bootstrap build TAG=latest
WORKDIR /opt/signy/bin


COPY bin/notary-wrapper.crt /etc/certs/notary/notary-wrapper.crt
COPY bin/notary-wrapper.key /etc/certs/notary/notary-wrapper.key




ENV DOCKER_HOST=tcp://localhost:2375
ENV DOCKER_TLS_CERTDIR=
#WORKDIR /

#ENTRYPOINT ["dockerd-entrypoint.sh & && /opt/signy/bin/signy webservice serve"]
CMD ["/opt/signy/bin/signy", "webservice", "serve"]

#COPY multipleProcess.sh multipleProcess.sh
#CMD ./multipleProcess.sh

#RUN ls /opt/signy/bin/
CMD sh -c 'dockerd-entrypoint.sh -D &' && /opt/signy/bin/signy webservice serve
