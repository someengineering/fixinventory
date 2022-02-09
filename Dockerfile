ARG UI_IMAGE_TAG=latest
FROM ghcr.io/someengineering/resoto-ui:${UI_IMAGE_TAG} as resoto-ui-env

FROM phusion/baseimage:focal-1.0.0 as build-env
ENV DEBIAN_FRONTEND=noninteractive
ARG SOURCE_COMMIT
ARG PYTHON_VERSION=3.10.2
ARG PYPY_VERSION=7.3.7
ARG ARANGODB_VERSION=3.8.4
ARG PROMETHEUS_VERSION=2.32.1

ENV PATH=/usr/local/db/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
COPY --from=resoto-ui-env /usr/local/resoto/ui /usr/local/resoto/ui
# Install Build dependencies
RUN apt-get update
RUN apt-get -y dist-upgrade
RUN apt-get -y install apt-utils
RUN apt-get -y install \
        build-essential \
        curl \
        unzip \
        zlib1g-dev \
        libncurses5-dev \
        libgdbm-dev \
        libgdbm-compat-dev \
        libnss3-dev \
        libreadline-dev \
        libsqlite3-dev \
        tk-dev \
        lzma \
        lzma-dev \
        liblzma-dev \
        uuid-dev \
        libbz2-dev \
        rustc \
        shellcheck \
        findutils \
        libtool \
        automake \
        autoconf \
        libffi-dev \
        libssl-dev \
        cargo \
        linux-headers-generic

# Download and install ArangoDB (graphdb)
WORKDIR /usr/local/db
RUN curl -L -o /tmp/arangodb.tar.gz https://download.arangodb.com/arangodb38/Community/Linux/arangodb3-linux-${ARANGODB_VERSION}.tar.gz
RUN tar xzvf /tmp/arangodb.tar.gz --strip-components=1 -C /usr/local/db

# Download and install Prometheus (tsdb)
WORKDIR /usr/local/tsdb
RUN curl -L -o /tmp/prometheus.tar.gz  https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz
RUN tar xzvf /tmp/prometheus.tar.gz --strip-components=1 -C /usr/local/tsdb
COPY docker/prometheus.yml /usr/local/tsdb/prometheus.yml

# Download and install CPython
WORKDIR /build/python
RUN curl -L -o /tmp/python.tar.gz  https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz
RUN tar xzvf /tmp/python.tar.gz --strip-components=1 -C /build/python
RUN ./configure --enable-optimizations --prefix /usr/local/python
RUN make -j 12
RUN make install
RUN /usr/local/python/bin/python3 -m ensurepip

# Download and install PyPy
WORKDIR /build
RUN mkdir -p /build/pypy
RUN curl -L -o /tmp/pypy.tar.bz2 https://downloads.python.org/pypy/pypy3.8-v${PYPY_VERSION}-linux64.tar.bz2
RUN tar xjvf /tmp/pypy.tar.bz2 --strip-components=1 -C /build/pypy
RUN mv /build/pypy /usr/local/pypy
RUN /usr/local/pypy/bin/pypy3 -m ensurepip

WORKDIR /usr/local
RUN /usr/local/python/bin/python3 -m venv resoto-venv-python3
RUN /usr/local/pypy/bin/pypy3 -m venv resoto-venv-pypy3

# Prepare PyPy whl build env
RUN mkdir -p /build-python
RUN mkdir -p /build-pypy

# Download and install Python test tools
RUN . /usr/local/resoto-venv-python3/bin/activate && python -m pip install -U pip poetry
RUN . /usr/local/resoto-venv-pypy3/bin/activate && pypy3 -m pip install -U pip poetry

# Build resotolib
COPY resotolib /usr/src/resotolib
WORKDIR /usr/src/resotolib
RUN . /usr/local/resoto-venv-python3/bin/activate && python -m poetry install
RUN . /usr/local/resoto-venv-pypy3/bin/activate && pypy3 -m poetry install

# Build resotocore
COPY resotocore /usr/src/resotocore
WORKDIR /usr/src/resotocore
RUN . /usr/local/resoto-venv-python3/bin/activate && python -m poetry install
RUN . /usr/local/resoto-venv-pypy3/bin/activate && pypy3 -m poetry install

# Build resotoworker
COPY resotoworker /usr/src/resotoworker
WORKDIR /usr/src/resotoworker
RUN . /usr/local/resoto-venv-python3/bin/activate && python -m poetry install

# Build resotometrics
COPY resotometrics /usr/src/resotometrics
WORKDIR /usr/src/resotometrics
RUN . /usr/local/resoto-venv-python3/bin/activate && python -m poetry install

# Build resotoshell
COPY resotoshell /usr/src/resotoshell
WORKDIR /usr/src/resotoshell
RUN . /usr/local/resoto-venv-python3/bin/activate && python -m poetry install

# Build resoto plugins
COPY plugins /usr/src/plugins
WORKDIR /usr/src
RUN for plugin_dir in $(find plugins/ -maxdepth 1 -mindepth 1 -type d); do \
        (cd "/usr/src/$plugin_dir"; . /usr/local/resoto-venv-python3/bin/activate && python -m poetry install) ;\
    done

# Copy image config and startup files
WORKDIR /usr/src/resoto
COPY docker/service.in /usr/local/etc/service.in
COPY docker/defaults /usr/local/etc/resoto/defaults
COPY docker/common /usr/local/etc/resoto/common
COPY docker/argsdispatcher /usr/local/bin/argsdispatcher
COPY docker/bootstrap /usr/local/sbin/bootstrap
COPY docker/bootstrap-graphdb /usr/local/sbin/bootstrap-graphdb
COPY docker/startup /usr/local/bin/startup
COPY docker/resh-shim /usr/local/bin/resh-shim
RUN chmod 755 /usr/local/bin/startup \
    /usr/local/bin/resh-shim \
    /usr/local/sbin/bootstrap \
    /usr/local/sbin/bootstrap-graphdb
COPY docker/dnsmasq.conf /usr/local/etc/dnsmasq.conf
COPY docker/syslog-ng.conf /usr/local/etc/syslog-ng.conf
RUN echo "${SOURCE_COMMIT:-unknown}" > /usr/local/etc/git-commit.HEAD


# Setup main image
FROM phusion/baseimage:focal-1.0.0
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG="en_US.UTF-8"
COPY --from=build-env /usr/local /usr/local
ENV PATH=/usr/local/python/bin:/usr/local/pypy/bin:/usr/local/db/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /
RUN groupadd -g "${PGID:-0}" -o resoto \
    && useradd -g "${PGID:-0}" -u "${PUID:-0}" -o --create-home resoto \
    && apt-get update \
    && apt-get -y --no-install-recommends install apt-utils \
    && apt-get -y dist-upgrade \
    && apt-get -y --no-install-recommends install \
        iproute2 \
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
    && ln -s /usr/local/bin/resh-shim /usr/bin/resh \
    && mv -f /usr/local/etc/syslog-ng.conf /etc/syslog-ng/syslog-ng.conf \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

EXPOSE 8900 8529 9955 9956
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/sbin/bootstrap"]
