build:
	cargo build
	sudo chown root target/debug/doas-rust
	sudo chmod 4755 target/debug/doas-rust

run:
	make build
	./target/debug/doas-rust