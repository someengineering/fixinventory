FROM python:3.8-alpine AS build-env
RUN apk add --no-cache build-base findutils linux-headers
RUN pip install --upgrade pip
RUN pip install tox flake8
COPY ./ /usr/src/cloudkeeper
WORKDIR /usr/src/cloudkeeper
RUN cd cloudkeeper/ && tox && pip wheel -w /build . && cd -
RUN cd plugins/aws/ && pip wheel -w /build -f /build . && cd -
RUN find plugins/ -name tox.ini | while read toxini; do cd $(dirname "$toxini") && tox && cd - || exit 1; done
RUN find plugins/ -maxdepth 1 -mindepth 1 -type d -print0 | xargs -0 pip wheel -w /build -f /build

FROM python:3.8-alpine
WORKDIR /
RUN apk add --no-cache dumb-init dnsmasq dcron dateutils
COPY --from=build-env /build /build
COPY docker/startup /usr/local/bin/startup
COPY docker/dnsmasq.conf /etc/dnsmasq.d/cloudkeeper.conf
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN pip install --upgrade pip \
    && pip install -f /build /build/*.whl \
    && chmod +x /usr/local/bin/startup \
    && rm -rf /build
ENTRYPOINT ["/usr/bin/dumb-init", "--",  "startup"]
