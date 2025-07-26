CC = gcc
CLANG = clang
LLC = llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

# Directories
LIBBPF_DIR = /usr/include
KERN_SRC = tcp_drop_kern.c
USER_SRC = tcp_drop_user.c
KERN_OBJ = tcp_drop_kern.o
USER_BIN = tcp_drop

# Compiler flags
CFLAGS = -g -O2 -Wall -Wextra
KERN_CFLAGS = -g -O2 -Wall \
	-I$(LIBBPF_DIR) \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-address-of-packed-member \
	-Wno-tautological-compare \
	-Wno-unknown-warning-option

# Libraries for userspace program
LIBS = -lbpf -lelf -lz

.PHONY: all clean install deps

all: $(KERN_OBJ) $(USER_BIN)

# Build kernel eBPF object
$(KERN_OBJ): $(KERN_SRC)
	$(CLANG) $(KERN_CFLAGS) -c $< -o $@

# Build userspace program
$(USER_BIN): $(USER_SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

# Build simple loader (alternative)
simple: $(SIMPLE_BIN)

$(SIMPLE_BIN): simple_loader.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

# Install dependencies (Ubuntu/Debian)
deps:
	@echo "Installing dependencies..."
	sudo apt update
	sudo apt install -y \
		clang \
		llvm \
		libbpf-dev \
		libelf-dev \
		build-essential \
		linux-headers-$(shell uname -r) \
		zlib1g-dev \
		pkg-config \
		linux-tools-common \
		linux-tools-$(shell uname -r)
	@echo "Dependencies installed successfully!"
	@echo "Checking libbpf version..."
	@pkg-config --modversion libbpf || echo "Warning: Could not determine libbpf version"
	@echo "Checking BTF support..."
	@ls /sys/kernel/btf/vmlinux >/dev/null 2>&1 && echo "BTF support: OK" || echo "BTF support: Missing (this might cause issues)"

# Load and run the program (requires root)
run: all
	@echo "Loading eBPF program (requires root privileges)..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Please run as root: sudo make run"; \
		exit 1; \
	fi
	./$(USER_BIN) eth0 4040

# Test with custom interface and port
test: all
	@echo "Usage: sudo ./$(USER_BIN) <interface> <port>"
	@echo "Example: sudo ./$(USER_BIN) eth0 8080"

# Clean build artifacts
clean:
	rm -f $(KERN_OBJ) $(USER_BIN) $(SIMPLE_BIN)

# Show kernel logs (to see dropped packets)
logs:
	sudo dmesg | tail -20 | grep -i "Dropping TCP packet" || echo "No drop messages found"

# Cleanup any existing XDP programs
cleanup-xdp:
	@echo "Cleaning up any existing XDP programs..."
	@sudo ip link set dev enp0s3 xdp off 2>/dev/null || true
	@sudo ip link set dev eth0 xdp off 2>/dev/null || true
	@echo "XDP cleanup completed"

# Show network interfaces
interfaces:
	ip link show

# Check system compatibility
check:
	@echo "System Compatibility Check:"
	@echo "=========================="
	@echo "Kernel version: $(shell uname -r)"
	@echo "Clang version: $(shell clang --version | head -1)"
	@echo "LLC version: $(shell llc --version | head -1)"
	@echo -n "libbpf version: "
	@pkg-config --modversion libbpf 2>/dev/null || echo "Not found via pkg-config"
	@echo -n "BTF support: "
	@ls /sys/kernel/btf/vmlinux >/dev/null 2>&1 && echo "Available" || echo "Missing (install linux-tools-common)"
	@echo -n "eBPF JIT: "
	@cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null && echo " (enabled)" || echo "Unknown"
	@echo "Interface check:"
	@ip link show | grep -E '^[0-9]+:' | head -3

# Generate test traffic (for testing)
generate-traffic:
	@echo "Generating test traffic on port 4040..."
	@echo "Run this in another terminal:"
	@echo "nc -l 4040  # Start server"
	@echo "nc localhost 4040  # Connect client"

help:
	@echo "eBPF TCP Port Dropper"
	@echo "===================="
	@echo ""
	@echo "Available targets:"
	@echo "  all          - Build kernel object and userspace program"
	@echo "  deps         - Install required dependencies (Ubuntu/Debian)"
	@echo "  check        - Check system compatibility"
	@echo "  cleanup-xdp  - Remove any existing XDP programs from interfaces"
	@echo "  run          - Load and run the program on eth0:4040 (requires root)"
	@echo "  test         - Show usage examples"
	@echo "  clean        - Clean build artifacts"
	@echo "  logs         - Show kernel logs for dropped packets"
	@echo "  interfaces   - List available network interfaces"
	@echo "  generate-traffic - Show commands to generate test traffic"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  1. Check system: make check"
	@echo "  2. Install dependencies: make deps"
	@echo "  3. Build: make"
	@echo "  4. Cleanup existing XDP: make cleanup-xdp"
	@echo "  5. Run: sudo ./$(USER_BIN) <interface> <port>"
	@echo ""
	@echo "Example:"
	@echo "  make cleanup-xdp"
	@echo "  sudo ./$(USER_BIN) enp0s3 4040"
