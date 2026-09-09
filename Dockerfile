# Linux (Debian bookworm) image with liboqs + the PQC HTTP API.
FROM golang:1.23.4 AS builder

ENV CGO_ENABLED=1 \
    GOTOOLCHAIN=local \
    LD_LIBRARY_PATH=/usr/local/lib \
    DEBIAN_FRONTEND=noninteractive \
    ACQUIRE_RETRIES=8

RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources; \
    elif [ -f /etc/apt/sources.list ]; then \
      sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends -o Acquire::Retries=${ACQUIRE_RETRIES} \
        cmake libssl-dev ninja-build; \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build /tmp/liboqs/build --parallel \
    && cmake --install /tmp/liboqs/build \
    && rm -rf /tmp/liboqs

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY .config/liboqs-go.linux.pc .config/liboqs-go.pc
ENV PKG_CONFIG_PATH=/src/.config

RUN go test ./... \
    && go build -o /out/qday-pqc-server .

FROM golang:1.23.4 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources; \
    elif [ -f /etc/apt/sources.list ]; then \
      sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends -o Acquire::Retries=8 curl libssl3; \
    rm -rf /var/lib/apt/lists/*; \
    echo /usr/local/lib > /etc/ld.so.conf.d/liboqs.conf; \
    useradd --system --home-dir /data --create-home pqc

COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
RUN ldconfig

COPY --from=builder /out/qday-pqc-server /usr/local/bin/qday-pqc-server
COPY config.docker.yaml /etc/qday-pqc-server/config.yaml

ENV PQC_CONFIG=/etc/qday-pqc-server/config.yaml \
    PQC_HTTP_ADDR=:8080 \
    PQC_ALGORITHM=ML-DSA-65 \
    PQC_LOG_LEVEL=info \
    LD_LIBRARY_PATH=/usr/local/lib

WORKDIR /data
USER pqc
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health >/dev/null

ENTRYPOINT ["/usr/local/bin/qday-pqc-server"]
CMD ["-config", "/etc/qday-pqc-server/config.yaml"]
