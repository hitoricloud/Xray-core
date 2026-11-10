FROM golang:1.26.7-alpine AS builder
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" ./main

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/xray /usr/local/bin/xray
ENTRYPOINT ["xray"]
