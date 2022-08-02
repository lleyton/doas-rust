build:
	cargo build
	sudo chown root target/debug/oko
	sudo chmod 4755 target/debug/oko

run *ARGS: build
	./target/debug/oko {{ARGS}}

test:
	cargo test