# CRI-O spike 00: a kindest/node image running CRI-O instead of containerd.
# Build args: NODE (digest-pinned kindest/node of the Kubernetes minor), VERSION (CRI-O, same minor).
ARG NODE

FROM alpine:3.22 AS dl
ARG VERSION
ARG TARGETARCH
RUN apk add --no-cache curl
WORKDIR /dl
RUN f=cri-o.${TARGETARCH}.v${VERSION}.tar.gz \
 && u=https://storage.googleapis.com/cri-o/artifacts \
 && curl -fsSLO ${u}/${f} && curl -fsSLO ${u}/${f}.sha256sum \
 && sha256sum -c ${f}.sha256sum && tar -xzf ${f}

FROM ${NODE}
COPY --from=dl /dl/cri-o /tmp/cri-o
# The bundle's install script is bash; it also replaces crictl and /etc/crictl.yaml, and only ships a disabled
# bridge CNI config, so kindnet stays the network. kind's entrypoint edits containerd's config on every boot, so
# containerd stays installed, only disabled.
RUN cd /tmp/cri-o && bash ./install && rm -rf /tmp/cri-o ~/.crio-install \
 && systemctl disable containerd && systemctl enable crio
# The node has no D-Bus daemon. crun's systemd cgroup driver needs one ("cannot open sd-bus"); runc's reaches
# systemd through /run/systemd/private, as it does under kind's containerd.
COPY 20-spike.conf /etc/crio/crio.conf.d/20-spike.conf
