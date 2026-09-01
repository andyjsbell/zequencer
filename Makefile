CARGO ?= cargo

.DEFAULT_GOAL := help
.PHONY: help check test unit integration adversarial demo pipeline bench docker fmt lint clean

help: ## List the available targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

## ── the gate ────────────────────────────────────────────────────────

check: fmt lint test ## Format, lint and test — must pass before every commit

## ── tests ───────────────────────────────────────────────────────────

test: ## Run every test: unit, integration and doc
	$(CARGO) test

unit: ## Run the in-module unit tests only
	$(CARGO) test --lib

integration: ## Run the end-to-end pipeline tests in tests/
	$(CARGO) test --test pipeline -- --nocapture

adversarial: ## Run the adversarial simulation — spam, races, forged submitters
	$(CARGO) test --test adversarial -- --nocapture

## ── running ─────────────────────────────────────────────────────────

pipeline: ## Serve the pipeline on :3000 — every stage running as a task
	$(CARGO) run

demo: ## Drive a whole intent over HTTP: submit, watch, receipt, replay
	@./scripts/demo.sh

docker: ## Serve the pipeline on :3000 in a container
	docker compose up --build

## ── measurement ─────────────────────────────────────────────────────

bench: ## Measure the submit path — latency and throughput
	$(CARGO) bench --bench submit

## ── housekeeping ────────────────────────────────────────────────────

fmt: ## Check formatting, without rewriting anything
	$(CARGO) fmt --check

lint: ## Clippy over every target, warnings are errors
	$(CARGO) clippy --all-targets -- -D warnings

clean: ## Remove build artefacts
	$(CARGO) clean
