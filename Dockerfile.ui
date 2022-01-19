FROM ubuntu:20.04 as build-env
ENV DEBIAN_FRONTEND=noninteractive
ARG TESTS
ARG SOURCE_COMMIT
ARG GODOT_VERSION=3.4
ARG CRYPTO_EXPORT_TEMPLATES_DEBUG_URI=https://github.com/someengineering/godot-webassembly-export-templates/releases/download/v0.1alpha1/webassembly_threads_debug.zip
ARG CRYPTO_EXPORT_TEMPLATES_RELEASE_URI=https://github.com/someengineering/godot-webassembly-export-templates/releases/download/v0.1alpha1/webassembly_threads_release.zip

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Install Build dependencies
RUN apt-get update
RUN apt-get -y dist-upgrade
RUN apt-get -y install apt-utils
RUN apt-get -y install \
        curl \
        unzip

# Download and install Godot
WORKDIR /build/godot
RUN mkdir -p /root/.local/share/godot/templates
RUN curl -L -o /tmp/godot.zip https://downloads.tuxfamily.org/godotengine/${GODOT_VERSION}/Godot_v${GODOT_VERSION}-stable_linux_headless.64.zip
RUN curl -L -o /tmp/godot.tpz https://downloads.tuxfamily.org/godotengine/${GODOT_VERSION}/Godot_v${GODOT_VERSION}-stable_export_templates.tpz
RUN curl -L -o /tmp/webassembly_threads_debug.zip ${CRYPTO_EXPORT_TEMPLATES_DEBUG_URI}
RUN curl -L -o /tmp/webassembly_threads_release.zip ${CRYPTO_EXPORT_TEMPLATES_RELEASE_URI}
RUN unzip /tmp/godot.zip -d /build/godot
RUN unzip /tmp/godot.tpz -d /root/.local/share/godot/templates
RUN mv /root/.local/share/godot/templates/templates /root/.local/share/godot/templates/${GODOT_VERSION}.stable
RUN mv -f /tmp/webassembly_threads_debug.zip /root/.local/share/godot/templates/${GODOT_VERSION}.stable/webassembly_threads_debug.zip
RUN mv -f /tmp/webassembly_threads_release.zip /root/.local/share/godot/templates/${GODOT_VERSION}.stable/webassembly_threads_release.zip

# Build resotoui
WORKDIR /usr/local/resoto/ui
COPY ui /usr/src/ui
RUN /build/godot/Godot_v${GODOT_VERSION}-stable_linux_headless.64 --path /usr/src/ui/src --export HTML5 /usr/local/resoto/ui/index.html

RUN echo "${SOURCE_COMMIT:-unknown}" > /usr/local/etc/git-commit.HEAD

# Setup main image
FROM ubuntu:20.04
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
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENTRYPOINT ["/bin/bash"]
