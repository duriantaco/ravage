FROM kalilinux/kali-rolling

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dirb \
        dnsutils \
        ffuf \
        git \
        gobuster \
        golang-go \
        hydra \
        iproute2 \
        iptables \
        jq \
        netcat-traditional \
        ncat \
        nikto \
        nmap \
        nuclei \
        openssh-client \
        openssl \
        python3 \
        python3-paramiko \
        python3-pexpect \
        python3-pip \
        sshpass \
        sqlmap \
        whatweb \
    && rm -rf /var/lib/apt/lists/*

RUN GOBIN=/usr/local/bin go install github.com/projectdiscovery/katana/cmd/katana@latest

RUN setcap -r /usr/lib/nmap/nmap || true

RUN set -eu; \
    for binary in curl python3 nmap ffuf katana nuclei sqlmap nikto openssl ncat; do \
        command -v "$binary" >/dev/null; \
    done
