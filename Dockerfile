FROM debian:stable-slim as build-env
ENV DEBIAN_FRONTEND=noninteractive
ARG TESTS
RUN apt-get update || true
RUN apt-get -y install apt-utils
RUN apt-get -y install build-essential \
    curl python3 python3-pip rustc shellcheck \
    findutils libtool automake autoconf \
    libffi-dev libssl-dev cargo linux-headers-5.10.0-8-amd64
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
WORKDIR /
RUN apt-get update || true \
    && apt-get -y --no-install-recommends install apt-utils \
    && apt-get -y dist-upgrade \
    && apt-get -y --no-install-recommends install python3 python3-pip dumb-init dnsmasq libffi7 openssl dateutils
COPY --from=build-env /build /build
COPY docker/startup /usr/local/bin/startup
COPY docker/dnsmasq.conf /etc/dnsmasq.d/cloudkeeper.conf
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN pip install --upgrade pip \
    && pip install -f /build /build/*.whl \
    && chmod +x /usr/local/bin/startup \
    && rm -rf /build
ENTRYPOINT ["/usr/bin/dumb-init", "--",  "startup"]
