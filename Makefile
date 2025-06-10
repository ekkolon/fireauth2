.PHONY: lint test serve

lint:
	cargo clippy --workspace --all-targets --all-features -- -Dwarnings

test:
	cargo test --workspace --all-targets --all-features

serve:
	cargo watch -w fireauth2-server -x "run"

serve_docker: 
	docker compose up

serve_docker_fresh:
	make clean_docker && \
	docker compose up --build

clean_docker:
	docker compose down

clean_all:
	cargo clean && \
	make clean_docker