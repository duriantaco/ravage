FROM alpine:3.22.1

RUN apk add --no-cache \
        curl \
        iptables \
        musl-utils \
    && command -v curl >/dev/null \
    && command -v getent >/dev/null \
    && command -v iptables >/dev/null

CMD ["sleep", "infinity"]
