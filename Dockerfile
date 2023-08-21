ARG GOARCH="amd64"
FROM golang:1.20 AS builder
# golang envs
ARG GOARCH="amd64"
ARG GOOS=linux
ENV CGO_ENABLED=0

WORKDIR /go/src/app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/tproxypod .

FROM debian:12
RUN apt-get update && \
      apt-get -y install iptables iproute2
COPY --from=builder --chown=root:root /go/bin/tproxypod /bin/tproxypod
CMD ["/bin/tproxypod"]
