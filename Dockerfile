FROM debian:stable-slim as build-env
ENV DEBIAN_FRONTEND=noninteractive
ARG TESTS
ARG ARANGODB_VERSION=3.8.0-1
RUN apt-get update || true
RUN apt-get -y install apt-utils
RUN apt-get -y install \
        build-essential \
        curl \
        python3 \
        python3-pip \
        rustc \
        shellcheck \
        findutils \
        libtool \
        automake \
        autoconf \
        libffi-dev \
        libssl-dev \
        cargo \
        linux-headers-5.10.0-8-amd64
RUN mkdir -p /build \
    && curl -L -o /build/arangodb.deb https://download.arangodb.com/arangodb38/Community/Linux/arangodb3_${ARANGODB_VERSION}_amd64.deb \
    && dpkg -i /build/arangodb.deb
RUN pip install --upgrade pip
RUN pip install tox flake8
COPY ./ /usr/src/cloudkeeper
WORKDIR /usr/src/cloudkeeper/keepercore
#RUN if [ "X${TESTS:-true}" = Xtrue ]; then tox; fi
RUN pip wheel -w /build .
WORKDIR /usr/src/cloudkeeper/cloudkeeper
RUN if [ "X${TESTS:-true}" = Xtrue ]; then tox; fi
RUN pip wheel -w /build .
WORKDIR /usr/src/cloudkeeper
RUN cd plugins/aws/ && pip wheel -w /build -f /build . && cd -
RUN if [ "X${TESTS:-true}" = Xtrue ]; then find plugins/ -name tox.ini | while read toxini; do cd $(dirname "$toxini") && tox && cd - || exit 1; done; fi
RUN find plugins/ -maxdepth 1 -mindepth 1 -type d -print0 | xargs -0 pip wheel -w /build -f /build

FROM debian:stable-slim
ENV DEBIAN_FRONTEND=noninteractive
COPY --from=build-env /build /build
COPY docker/startup /usr/local/bin/startup
COPY docker/dnsmasq.conf /etc/dnsmasq.d/cloudkeeper.conf
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /
RUN apt-get update || true \
    && apt-get -y --no-install-recommends install apt-utils \
    && apt-get -y dist-upgrade \
    && apt-get -y --no-install-recommends install \
        python3-minimal \
        python3-pip \
        dumb-init \
        dnsmasq \
        libffi7 \
        openssl \
        procps \
        dateutils \
        curl \
        jq \
        cron \
        ca-certificates \
        openssh-client \
        locales \
        unzip \
    && echo 'LANG="en_US.UTF-8"' > /etc/default/locale \
    && echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen \
    && rm -f /bin/sh \
    && ln -s /bin/bash /bin/sh \
    && locale-gen \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3 1 \
    && mkdir -p /var/spool/cron/crontabs \
    && pip install --upgrade pip \
    && pip install -f /build /build/*.whl \
    && dpkg -i /build/arangodb.deb \
    && chmod +x /usr/local/bin/startup \
    && apt-get clean \
    && rm -rf /build /var/lib/apt/lists/* /tmp/* /var/tmp/*
ENTRYPOINT ["/usr/bin/dumb-init", "--",  "startup"]
