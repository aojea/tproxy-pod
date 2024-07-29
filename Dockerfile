ARG GOARCH="amd64"

FROM ubuntu:22.04 AS ebpf-builder
WORKDIR /go/src/app
RUN apt-get update && apt-get -y install clang llvm
COPY ./bpf ./bpf
RUN clang -target bpf -g -Wall -O2 -c bpf/sockproxy.c -o bpf/sockproxy.o

FROM golang:1.22 AS builder
# golang envs
ARG GOARCH="amd64"
ARG GOOS=linux
ENV CGO_ENABLED=0

WORKDIR /go/src/app
COPY ./main.go ./go.mod ./go.sum ./
RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/tproxy .

FROM registry.k8s.io/build-image/distroless-iptables:v0.5.6
COPY --from=ebpf-builder --chown=root:root /go/src/app/bpf/sockproxy.o /bpf/sockproxy.o
COPY --from=builder --chown=root:root /go/bin/tproxy /tproxy
CMD ["/tproxy"]
