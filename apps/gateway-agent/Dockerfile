FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /gateway-agent ./cmd/agent

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /gateway-agent /usr/local/bin/gateway-agent
ENTRYPOINT ["/usr/local/bin/gateway-agent"]
