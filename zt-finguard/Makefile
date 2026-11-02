# ZT-FinGuard - run `make help`
ENGINE ?= docker
COMPOSE = $(ENGINE) compose
SERVICES = gateway dashboard auth account transaction risk audit

.PHONY: help setup certs rotate-certs secrets train build up down logs ps scan falco test opa-test users clean

help:
	@echo "make setup          generate internal CA, service certs and secrets"
	@echo "make build          build all images (ENGINE=docker|podman)"
	@echo "make up             start the stack -> https://localhost:8501"
	@echo "make users          print demo users + current authenticator codes"
	@echo "make test           end-to-end Zero Trust tests against the running stack"
	@echo "make opa-test       unit-test the authorization policy"
	@echo "make scan           Trivy scan of every image (fails on CRITICAL)"
	@echo "make falco          start Falco runtime monitoring (rootful only)"
	@echo "make rotate-certs   re-issue all service certificates and restart"
	@echo "make train DATA=... retrain the risk model (real PaySim CSV)"
	@echo "make down / clean   stop / stop and delete data"

setup: certs secrets

certs:
	./scripts/gen-certs.sh

rotate-certs:
	./scripts/gen-certs.sh --rotate
	$(COMPOSE) up -d --force-recreate

secrets:
	./scripts/gen-secrets.sh

DATA ?= data/paysim_sample.csv
train:
	cd services/risk && ( [ -f "$(DATA)" ] || python3 make_sample.py --out $(DATA) ) && python3 train.py --data $(DATA)

build:
	$(COMPOSE) build

up:
	$(COMPOSE) up -d --build
	@echo "Dashboard: https://localhost:8501   API: https://localhost:8443"
	@echo "Browser will warn about the private CA - import certs/ca.crt to trust it."

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=50

ps:
	$(COMPOSE) ps

users:
	@python3 scripts/demo-users.py

test:
	LOGIN_RATE_LIMIT_PER_MIN=1000 python3 -m pytest -v tests/

opa-test:
	$(ENGINE) run --rm -v $(PWD)/policies:/policies:ro docker.io/openpolicyagent/opa:1.4.2-static test /policies -v

scan:
	ENGINE=$(ENGINE) ./scripts/scan-images.sh

falco:
	$(COMPOSE) --profile runtime up -d falco

clean:
	$(COMPOSE) --profile runtime down -v
