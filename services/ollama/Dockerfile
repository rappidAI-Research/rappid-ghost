# Reviewed CPU-only service preparation, not an accepted agent image.
FROM --platform=linux/amd64 golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS compiler
ARG SOURCE_DATE_EPOCH=0
ADD --checksum=sha256:296dc8dd88a617335d9132412179f11926d266941d53a4727917fd18ac675053 https://codeload.github.com/ollama/ollama/tar.gz/refs/tags/v0.40.16 /tmp/source.tar.gz
RUN --network=none mkdir /src && tar -xzf /tmp/source.tar.gz -C /src --strip-components=1 && rm /tmp/source.tar.gz
WORKDIR /src
COPY go.mod.lock go.mod
COPY go.sum.lock go.sum
ENV GOTOOLCHAIN=local GOWORK=off GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org CGO_ENABLED=1
# Dependency retrieval is a trusted preparation phase, never agent execution.
# The checked-in graph/sums select every module; no go generate/install scripts.
RUN go mod download && go mod verify
RUN --network=none go build -mod=readonly -trimpath -buildvcs=false -buildmode=pie -ldflags='-s -w -X github.com/ollama/ollama/version.Version=0.40.16-ghost.1' -o /patched-ollama . && go version -m /patched-ollama > /go-buildinfo.txt

FROM --platform=linux/amd64 ollama/ollama:0.40.16@sha256:910d0d8107b538fb0894e63163eb195de0cc7aefcbc666dc62d3b18f71124592 AS cpu
ARG SOURCE_DATE_EPOCH=0
# Actually remove the vulnerable package manager/library, not scanner metadata.
# Keep the upstream CPU backend and its distro package inventory for scanning.
RUN --network=none dpkg --purge apt libapt-pkg6.0t64 && rm -rf /usr/lib/ollama/cuda* /usr/lib/ollama/rocm* /usr/lib/ollama/vulkan* /usr/lib/ollama/mlx* && test ! -e /usr/bin/apt && test ! -e /usr/bin/apt-get
COPY --from=compiler /patched-ollama /usr/bin/ollama
COPY --from=compiler /go-buildinfo.txt /usr/share/ghost-ollama/go-buildinfo.txt

# Flatten away deleted GPU payloads while retaining real dpkg/Go inventories.
FROM scratch
ARG SOURCE_DATE_EPOCH=0
COPY --from=cpu / /
LABEL org.opencontainers.image.version="0.40.16-ghost.1" org.opencontainers.image.source="https://github.com/rappidAI-Research/rappid-ghost" ghost.ollama.source-sha256="296dc8dd88a617335d9132412179f11926d266941d53a4727917fd18ac675053" ghost.ollama.x-net="v0.62.0"
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin OLLAMA_HOST=0.0.0.0:11434 OLLAMA_NO_CLOUD=1
ENTRYPOINT ["/usr/bin/ollama"]
CMD ["serve"]
