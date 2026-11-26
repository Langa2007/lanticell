FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY packages/detector-sdk ./packages/detector-sdk
COPY apps/bot-engine ./apps/bot-engine
WORKDIR /app/apps/bot-engine
RUN CGO_ENABLED=0 go build -o /botd ./cmd/botd

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /botd /usr/local/bin/botd
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/botd"]
