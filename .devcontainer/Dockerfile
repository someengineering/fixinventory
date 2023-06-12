FROM mcr.microsoft.com/devcontainers/python:3.11

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


RUN wget -qO- https://download.arangodb.com/arangodb310/DEBIAN/Release.key | apt-key add -
RUN echo 'deb https://download.arangodb.com/arangodb310/DEBIAN/ /' | tee /etc/apt/sources.list.d/arangodb.list
RUN apt-get install -y apt-transport-https
RUN apt-get update
RUN apt-get install -y arangodb3-client

COPY requirements-all.txt /tmp/resoto-requirements.txt

# Install infrequently changing requirements
RUN su vscode -c 'pip3 install --no-warn-script-location -U pip wheel poetry' \
    && su vscode -c 'pip3 --disable-pip-version-check --no-cache-dir install --no-warn-script-location -U -r /tmp/resoto-requirements.txt' \
    && rm -rf /tmp/resoto-requirements.txt
