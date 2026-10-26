FROM golang:1.27.3-alpine AS builder
WORKDIR /app
ENV CGO_ENABLED=0 GOWORK=off GOEXPERIMENT=jsonv2 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=dev
RUN go build -mod=readonly -trimpath \
    -tags "sing xray with_quic with_grpc with_utls with_wireguard with_acme with_gvisor" \
    -ldflags "-s -w -X github.com/Designdocs/N2X/cmd.version=${VERSION}" \
    -o /out/N2X .

FROM alpine
ARG VERSION=dev
ARG VCS_REF=unknown
LABEL org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.source="https://github.com/Designdocs/N2X"
RUN apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir -p /etc/N2X/
COPY --from=builder /out/N2X /usr/local/bin/N2X
ENTRYPOINT ["N2X", "server", "--config", "/etc/N2X/config.json"]
