SHELL := /bin/bash

.PHONY: dev-up dev-down build test lint clean

dev-up:
	docker compose -f deployments/compose/compose.yaml up --build -d

dev-down:
	docker compose -f deployments/compose/compose.yaml down

build:
	mkdir -p bin
	cd apps/control-api && go build -o ../../bin/control-api ./cmd/api
	cd apps/gateway-agent && go build -o ../../bin/gateway-agent ./cmd/agent
	cd apps/bot-engine && go build -o ../../bin/botd ./cmd/botd
	cd apps/dashboard && npm run build

test:
	cd packages/event-schema && go vet ./...
	cd packages/detector-sdk && go vet ./...
	cd apps/control-api && go test -v ./...
	cd apps/gateway-agent && go test -v ./...
	cd apps/bot-engine && go test -v ./...
	cd apps/dashboard && npm test

lint:
	cd packages/event-schema && go vet ./...
	cd packages/detector-sdk && go vet ./...
	cd apps/control-api && go vet ./...
	cd apps/gateway-agent && go vet ./...
	cd apps/bot-engine && go vet ./...

clean:
	rm -rf bin apps/dashboard/dist
