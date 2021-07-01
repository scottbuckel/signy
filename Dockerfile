FROM docker:20.10-dind




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
COPY bin/root-ca.crt /etc/certs/notary/root-ca.crt
#COPY bin/root-ca.crt /etc/certs/notary/notary-server-svc





ENV DOCKER_HOST=tcp://localhost:2375
ENV DOCKER_TLS_CERTDIR=
#WORKDIR /

#ENTRYPOINT ["dockerd-entrypoint.sh & && /opt/signy/bin/signy webservice serve"]
#CMD ["/opt/signy/bin/signy", "webservice", "serve"]

#COPY multipleProcess.sh multipleProcess.sh
#CMD ./multipleProcess.sh

#RUN ls /opt/signy/bin/






# busybox "ip" is insufficient:
#   [rootlesskit:child ] error: executing [[ip tuntap add name tap0 mode tap] [ip link set tap0 address 02:50:00:00:00:01]]: exit status 1
RUN apk add --no-cache iproute2

# "/run/user/UID" will be used by default as the value of XDG_RUNTIME_DIR
RUN mkdir /run/user && chmod 1777 /run/user

# create a default user preconfigured for running rootless dockerd
RUN set -eux; \
	adduser -h /home/rootless -g 'Rootless' -D -u 1000 rootless; \
	echo 'rootless:100000:65536' >> /etc/subuid; \
	echo 'rootless:100000:65536' >> /etc/subgid

RUN set -eux; \
	\
	apkArch="$(apk --print-arch)"; \
	case "$apkArch" in \
		'x86_64') \
			url='https://download.docker.com/linux/static/stable/x86_64/docker-rootless-extras-20.10.7.tgz'; \
			;; \
		*) echo >&2 "error: unsupported architecture ($apkArch)"; exit 1 ;; \
	esac; \
	\
	wget -O rootless.tgz "$url"; \
	\
	tar --extract \
		--file rootless.tgz \
		--strip-components 1 \
		--directory /usr/local/bin/ \
		'docker-rootless-extras/rootlesskit' \
		'docker-rootless-extras/rootlesskit-docker-proxy' \
		'docker-rootless-extras/vpnkit' \
	; \
	rm rootless.tgz; \
	\
	rootlesskit --version; \
	vpnkit --version

# pre-create "/var/lib/docker" for our rootless user
RUN set -eux; \
	mkdir -p /home/rootless/.local/share/docker; \
	chown -R rootless:rootless /home/rootless/.local/share/docker
VOLUME /home/rootless/.local/share/docker
USER rootless


# "/run/user/UID" will be used by default as the value of XDG_RUNTIME_DIR
RUN mkdir /home/rootless/.signy && chmod 1777 /home/rootless/.signy

CMD sh -c 'dockerd-entrypoint.sh -D &' && /opt/signy/bin/signy webservice serve

