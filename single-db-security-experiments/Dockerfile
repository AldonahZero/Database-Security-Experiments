FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC \
    PATH="/root/.local/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    software-properties-common \
    python3 \
    python3-pip \
    python3-psycopg2 \
    python3-venv \
    curl \
    git \
    sqlmap \
    hydra \
    tcpdump \
    jq \
    && add-apt-repository -y ppa:oisf/suricata-stable \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
    suricata \
    && pip3 install --no-cache-dir \
    flask \
    pymongo \
    requests \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root

COPY attack-scripts /root/attack-scripts
COPY attack_client/vuln_app.py /root/vuln_app.py

RUN chmod +x /root/attack-scripts/*.py || true

CMD ["/bin/bash"]
