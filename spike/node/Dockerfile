# Spike 00: the pinned kindest/node with its containerd binaries replaced by a release.
ARG NODE=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5

FROM alpine:3.22 AS dl
ARG VERSION
ARG TARGETARCH
RUN apk add --no-cache curl
WORKDIR /dl
RUN f=containerd-${VERSION}-linux-${TARGETARCH}.tar.gz \
 && u=https://github.com/containerd/containerd/releases/download/v${VERSION} \
 && curl -fsSLO ${u}/${f} && curl -fsSLO ${u}/${f}.sha256sum \
 && sha256sum -c ${f}.sha256sum && mkdir out && tar -xzf ${f} -C out

FROM ${NODE}
# The node keeps containerd in /usr/local/bin; the tarball's bin/ has the same names.
COPY --from=dl /dl/out/bin/containerd /dl/out/bin/containerd-shim-runc-v2 /dl/out/bin/ctr /usr/local/bin/
