# ---
# Stage 1: Install certs, build binary, create default config file
# ---
FROM golang:1.13.6-alpine3.11 AS builder
RUN apk --update add git make ca-certificates
RUN mkdir -p /go/src/github.com/anuvu/zot
WORKDIR /go/src/github.com/anuvu/zot
COPY . .
RUN CGO_ENABLED=0 make clean binary
RUN echo -e '# Default config file for zot server\n\
http:\n\
  address: 0.0.0.0\n\
  port: 5000\n\
storage:\n\
  rootDirectory: /var/lib/registry' > config.yml && cat config.yml

# ---
# Stage 2: Final image with nothing but certs, binary, and default config file
# ---
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/src/github.com/anuvu/zot/bin/zot /zot
COPY --from=builder /go/src/github.com/anuvu/zot/config.yml /etc/zot/config.yml
ENTRYPOINT ["/zot"]
EXPOSE 5000
VOLUME ["/var/lib/registry"]
CMD ["serve", "/etc/zot/config.yml"]
