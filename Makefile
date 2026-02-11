CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Werror

# 获取架构
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# 目标二进制名
APP := netmonitor

.PHONY: all
all: vmlinux gen build

.PHONY: vmlinux
vmlinux:
	mkdir -p headers
	# 尝试生成 vmlinux.h，如果失败则提示用户
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h || \
	(echo "Error: Failed to generate vmlinux.h. Ensure kernel has CONFIG_DEBUG_INFO_BTF=y." && exit 1)

.PHONY: gen
gen:
	# 使用 go generate 调用 bpf2go
	go generate ./...

.PHONY: build
build:
	go build -o $(APP)

.PHONY: clean
clean:
	rm -f $(APP)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_x86_bpfel.go bpf_bpfel.o bpf_bpfeb.o bpf_x86_bpfel.o
	rm -rf headers
