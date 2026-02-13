BINARY_NAME := netmonitor
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
HEADER_DIR := headers

.PHONY: all clean build generate vmlinux

all: build

vmlinux:
	@echo "  GEN     vmlinux.h"
	@mkdir -p $(HEADER_DIR)
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(HEADER_DIR)/vmlinux.h

generate: vmlinux
	@echo "  GEN     Go bindings"
	@go generate ./...

build: generate
	@echo "  BUILD   $(BINARY_NAME)"
	@go build -o $(BINARY_NAME)

clean:
	@rm -f $(BINARY_NAME)
	@rm -f bpf_*.go bpf_*.o
	@rm -rf $(HEADER_DIR)
