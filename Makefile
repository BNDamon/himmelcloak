.PHONY: native build all-features test pam-smoke lint fmt oracle-up oracle-down test-live test-live-verbose docker-lint

COMPOSE = docker compose -f tests/keycloak/docker-compose.yml

native:
	scripts/build-native.sh

build: native
	scripts/with-native.sh cargo build --locked --workspace

all-features: native
	scripts/with-native.sh cargo build --locked --workspace --all-features

test: native
	scripts/with-native.sh cargo test --locked --workspace --tests

pam-smoke:
	bash crates/pam_himmelcloak/tests/pam-load-smoke.sh "$(CURDIR)"

lint: native
	scripts/with-native.sh cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
	cargo fmt --all --check

fmt:
	cargo fmt --all

oracle-up:
	tests/keycloak/bootstrap-cert.sh
	$(COMPOSE) up -d --pull always --force-recreate keycloak

oracle-down:
	$(COMPOSE) down -v

test-live:
	tests/keycloak/run.sh

test-live-verbose:
	tests/keycloak/run.sh --verbose

docker-lint:
	$(COMPOSE) build tester
	docker run --rm -v "$(CURDIR):/work" -e CARGO_TARGET_DIR=/tmp/himmelcloak-target -w /work himmelcloak-tester:ci cargo fmt --all --check
	docker run --rm -v "$(CURDIR):/work" -v himmelcloak-cargo-target:/tmp/himmelcloak-target -e CARGO_TARGET_DIR=/tmp/himmelcloak-target -w /work himmelcloak-tester:ci cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
