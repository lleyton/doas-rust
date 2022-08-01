build:
	cargo build
	sudo chown root target/debug/doas-rust
	sudo chmod 4755 target/debug/doas-rust

run *ARGS: build
	./target/debug/doas-rust {{ARGS}}