.PHONY: dev-server dev-web test test-server test-web e2e turn-test lint build images up down

dev-server: ## Run the relay locally on :8080
	cd server && DOOMMSG_DB=dev.db go run ./cmd/doommsg-server

dev-web: ## Run the web client with hot reload on :5173 (proxies /api to :8080)
	cd web && npm run dev

test: test-server test-web ## Unit tests for everything

test-server:
	cd server && go test -race -count=1 ./...

test-web:
	cd web && npm test

e2e: ## Two-browser end-to-end test against the real relay
	cd web && npm run build && npx playwright test

turn-test: ## Smoke-test coturn as deployed (needs deploy/.env and Docker)
	cd deploy && ./coturn/smoke-test.sh

lint:
	cd server && test -z "$$(gofmt -l .)" && go vet ./...
	cd web && npm run typecheck && npm run lint

build:
	cd server && CGO_ENABLED=0 go build -trimpath -o doommsg-server ./cmd/doommsg-server
	cd web && npm run build

images:
	cd deploy && docker compose build

up: ## Production stack (needs deploy/.env)
	cd deploy && docker compose up -d

down:
	cd deploy && docker compose down
