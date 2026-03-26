# Floodles - Master build file
# Builds all native components: C sender, Rust packet builder, Go engine

.PHONY: all c rust go clean check

all: check c rust go
	@echo ""
	@echo "[+] All native components built."
	@echo "    C sender   : native/c/libsender.so"
	@echo "    Rust lib   : native/rust/target/release/libfloodles_packets.so"
	@echo "    Go engine  : native/go/floodles-engine"

# --- Dependency checks ---
check:
	@echo "[*] Checking toolchains..."
	@which gcc   > /dev/null 2>&1 && echo "    gcc:   OK" || echo "    gcc:   NOT FOUND (C sender will be skipped)"
	@which cargo > /dev/null 2>&1 && echo "    cargo: OK" || echo "    cargo: NOT FOUND (Rust builder will be skipped)"
	@which go    > /dev/null 2>&1 && echo "    go:    OK" || echo "    go:    NOT FOUND (Go engine will be skipped)"

# --- C sender ---
c:
	@if which gcc > /dev/null 2>&1; then \
		echo "[*] Building C sender..."; \
		$(MAKE) -C native/c libsender.so; \
		echo "[+] C sender built: native/c/libsender.so"; \
	else \
		echo "[-] Skipping C sender (gcc not found)"; \
	fi

# Standalone C binary (for testing without Python)
c-standalone:
	@$(MAKE) -C native/c sender
	@echo "[+] C standalone binary: native/c/sender"

# --- Rust packet builder ---
rust:
	@if which cargo > /dev/null 2>&1; then \
		echo "[*] Building Rust packet builder (this may take 30-60s)..."; \
		cd native/rust && cargo build --release 2>&1 | tail -3; \
		echo "[+] Rust lib built: native/rust/target/release/libfloodles_packets.so"; \
	else \
		echo "[-] Skipping Rust builder (cargo not found)"; \
	fi

# --- Go engine ---
go:
	@if which go > /dev/null 2>&1; then \
		echo "[*] Building Go engine..."; \
		cd native/go && go build -ldflags="-s -w" -o floodles-engine .; \
		echo "[+] Go engine built: native/go/floodles-engine"; \
	else \
		echo "[-] Skipping Go engine (go not found)"; \
	fi

# --- Clean ---
clean:
	$(MAKE) -C native/c clean
	cd native/rust && cargo clean
	rm -f native/go/floodles-engine
