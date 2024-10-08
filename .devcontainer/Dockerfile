FROM mcr.microsoft.com/devcontainers/python:3.12

ARG USERNAME=vscode

# keep the bash history between container rebuilds
RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
    && mkdir /commandhistory \
    && touch /commandhistory/.bash_history \
    && chown -R $USERNAME /commandhistory \
    && echo "$SNIPPET" >> "/home/$USERNAME/.bashrc"

ENV PYTHONUNBUFFERED 1

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends vim wget


RUN wget -qO- https://download.arangodb.com/arangodb311/DEBIAN/Release.key | apt-key add -
RUN echo 'deb https://download.arangodb.com/arangodb311/DEBIAN/ /' | tee /etc/apt/sources.list.d/arangodb.list
RUN apt-get install -y apt-transport-https
RUN apt-get update
RUN apt-get install -y arangodb3-client

WORKDIR /build/awscli
RUN if [ "${TARGETPLATFORM}" = "linux/amd64" ]; then \
    export AWSCLI_ARCH=x86_64; \
    elif [ "${TARGETPLATFORM}" = "linux/arm64" ]; then \
    export AWSCLI_ARCH=aarch64; \
    else \
    export AWSCLI_ARCH=x86_64; \
    fi; \
    curl -L -o /tmp/awscliv2.zip https://awscli.amazonaws.com/awscli-exe-linux-${AWSCLI_ARCH}.zip
RUN unzip /tmp/awscliv2.zip
RUN aws/install -i /usr/local/aws-cli -b /usr/local/bin

RUN su vscode -c 'curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y' \
    && su vscode -c '$HOME/.cargo/bin/cargo install --features=ssl websocat'

# Install infrequently changing requirements
COPY requirements-all.txt /tmp/fix-requirements.txt
RUN su vscode -c 'pip3 install --no-warn-script-location -U pip wheel poetry' \
    && su vscode -c 'pip3 --disable-pip-version-check --no-cache-dir install --no-warn-script-location -U -r /tmp/fix-requirements.txt' \
    && rm -rf /tmp/fix-requirements.txt
