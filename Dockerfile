FROM golang:1.13 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl \
      git \
      bash \
      && rm -rf /var/lib/apt/lists/*

RUN curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s v1.17.1

FROM builder AS build-and-test

RUN mkdir -p /go/src/github.com/anuvu/zot
WORKDIR /go/src/github.com/anuvu/zot

COPY . .

RUN make test && make clean
ENV CGO_ENABLED 0
RUN make binary

FROM alpine:3.9 as certs
RUN apk --update add ca-certificates

FROM scratch

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=build-and-test /go/src/github.com/anuvu/zot/bin/zot /zot
EXPOSE 5000

ENTRYPOINT ["/zot"]
