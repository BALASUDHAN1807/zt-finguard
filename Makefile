# ZT-FinGuard - run `make help`
ENGINE ?= docker
IMAGE_PREFIX ?= $(shell grep -s '^IMAGE_PREFIX=' .env | cut -d= -f2)
COMPOSE = $(ENGINE) compose $(if $(shell grep -s "^SITE_DOMAIN=" .env),-f compose.yaml -f compose.cloud.yaml,)
SERVICES = gateway dashboard auth account transaction risk audit

.PHONY: push pull help deploy deploy-cloud status setup certs rotate-certs secrets train build up down logs ps scan falco test opa-test users clean

help:
	@echo "make deploy         one-command local deploy (checks, certs, build, health)"
	@echo "make deploy-cloud   on a cloud VM: see docs/deploy-cloud.md"
	@echo "make status         container health"
	@echo "make setup          generate internal CA, service certs and secrets"
	@echo "make build          build all images (ENGINE=docker|podman)"
	@echo "make push           build amd64+arm64 images and push to Docker Hub (IMAGE_PREFIX=bala1807/zt-finguard-)"
	@echo "make pull           pull the pushed images (IMAGE_PREFIX in .env)"
	@echo "make up             start the stack -> https://localhost:8501"
	@echo "make users          print demo users + current authenticator codes"
	@echo "make test           end-to-end Zero Trust tests against the running stack"
	@echo "make opa-test       unit-test the authorization policy"
	@echo "make scan           Trivy scan of every image (fails on CRITICAL)"
	@echo "make falco          start Falco runtime monitoring (rootful only)"
	@echo "make rotate-certs   re-issue all service certificates and restart"
	@echo "make train DATA=... retrain the risk model (real PaySim CSV)"
	@echo "make down / clean   stop / stop and delete data"

deploy:
	./deploy.sh

push:
	IMAGE_PREFIX=$(IMAGE_PREFIX) ./scripts/push-images.sh

pull:
	IMAGE_PREFIX=$(IMAGE_PREFIX) $(COMPOSE) pull

deploy-cloud:
	./deploy/cloud-setup.sh

status:
	./deploy.sh --status

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

# The suite signs in ~25 times: run it with a relaxed sign-in limit, then restore the real one.
test:
	@[ -x .venv/bin/pytest ] || (python3 -m venv .venv && .venv/bin/pip install -q pytest==8.3.4 httpx==0.28.1 pyotp==2.9.0)
	LOGIN_RATE_LIMIT_PER_MIN=1000 $(COMPOSE) up -d --no-deps gateway
	@until python3 -c "import ssl,urllib.request as u; u.urlopen('https://localhost:8443/healthz', context=ssl.create_default_context(cafile='certs/ca.crt'), timeout=2)" 2>/dev/null; do sleep 2; done
	ZT_DOCKER=1 IMAGE_PREFIX=$(IMAGE_PREFIX) .venv/bin/pytest -v tests/; rc=$$?; $(COMPOSE) up -d --no-deps gateway; exit $$rc

opa-test:
	$(ENGINE) run --rm -v $(PWD)/policies:/policies:ro docker.io/openpolicyagent/opa:1.4.2-static test /policies -v

scan:
	ENGINE=$(ENGINE) ./scripts/scan-images.sh

falco:
	$(COMPOSE) --profile runtime up -d falco

clean:
	$(COMPOSE) --profile runtime down -v
