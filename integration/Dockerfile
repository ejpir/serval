FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG GO_VERSION=1.26.1
ARG ZIG_VERSION=0.16.0-dev.2821+3edaef9e0
ARG ZIG_ARCHIVE=integration/toolchains/zig-x86_64-linux-0.16.0-dev.2821+3edaef9e0.tar.xz
ARG HEY_VERSION=v0.1.4
ARG H2SPEC_VERSION=v2.2.1+incompatible
ARG GRPCURL_VERSION=latest

ENV PATH=/usr/local/go/bin:/usr/local/zig:${PATH}
ENV GOBIN=/usr/local/bin
ENV GOCACHE=/var/cache/serval/go-build
ENV GOMODCACHE=/var/cache/serval/go-mod
ENV ZIG_GLOBAL_CACHE_DIR=/var/cache/serval/zig-global
ENV HOME=/root

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        curl \
        git \
        libssl-dev \
        nghttp2-client \
        patch \
        pkg-config \
        xz-utils && \
    command -v h2load >/dev/null && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

COPY ${ZIG_ARCHIVE} /tmp/zig.tar.xz
COPY integration/toolchains/zig-0.16.0-dev.2821+3edaef9e0-uring.patch /tmp/zig-uring.patch

RUN tar -C /usr/local -xf /tmp/zig.tar.xz && \
    if ! grep -q "const BatchNetReceivePending" "/usr/local/zig-x86_64-linux-${ZIG_VERSION}/lib/std/Io/Uring.zig"; then \
        patch -p0 -d /usr/local < /tmp/zig-uring.patch; \
    fi && \
    ln -s /usr/local/zig-x86_64-linux-${ZIG_VERSION}/zig /usr/local/bin/zig && \
    ln -s /usr/local/zig-x86_64-linux-${ZIG_VERSION} /usr/local/zig && \
    rm /tmp/zig.tar.xz /tmp/zig-uring.patch

RUN mkdir -p "${GOCACHE}" "${GOMODCACHE}" "${ZIG_GLOBAL_CACHE_DIR}"

RUN go install github.com/rakyll/hey@${HEY_VERSION} && \
    go install github.com/summerwind/h2spec/cmd/h2spec@${H2SPEC_VERSION} && \
    go install github.com/fullstorydev/grpcurl/cmd/grpcurl@${GRPCURL_VERSION}

RUN mkdir -p /tmp/serval-go-prewarm && \
    printf '%s\n' \
        'module example.com/serval-integration-prewarm' \
        '' \
        'go 1.23' \
        '' \
        'require (' \
        '    google.golang.org/grpc v1.76.0' \
        '    google.golang.org/protobuf v1.36.10' \
        ')' > /tmp/serval-go-prewarm/go.mod && \
    cd /tmp/serval-go-prewarm && \
    go mod download && \
    rm -rf /tmp/serval-go-prewarm

WORKDIR /work/serval

CMD ["bash"]
