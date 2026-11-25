FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /control-api ./cmd/api

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /control-api /usr/local/bin/control-api
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/control-api"]
