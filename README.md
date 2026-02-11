# eBPF Network Monitor (NetMonitor)

**NetMonitor** 是一个基于 eBPF (CO-RE) 技术构建的高性能 Linux 网络监控工具。它能够实时捕获系统中的 TCP 连接请求 (`connect`) 和 UDP 通信（如 DNS 查询），并精确关联到发起请求的进程及其**完整命令行参数**。

与传统的 `netstat` 或 `ss` 不同，NetMonitor 基于事件驱动（Event-driven），可以在网络请求发生的瞬间进行捕获，甚至能捕捉到生命周期极短的进程。

## ✨ 功能特性

- **实时监控**：
  - **TCP**: 监控 IPv4/IPv6 的 `connect` 系统调用。
u - **UDP**: 监控 `sendto` 系统调用（智能过滤 DNS 等特定流量）。
- **深度信息关联**：
  - 直接从内核态读取进程的 `mm_struct`，获取**完整的命令行参数**（如 `curl -v https://...`），而非仅仅是截断的进程名。
  - 若无法读取内存（如内核线程），自动回退到 `comm`（短进程名）。
- **高性能 & 安全**：
  - 使用 eBPF CO-RE (Compile Once – Run Everywhere) 技术，开销极低。
  - 无需修改内核源码或加载内核模块（Kernel Module）。

## 🛠 系统要求

由于使用了 eBPF CO-RE 特性，运行环境需要满足以下条件：

- **操作系统**: Linux (推荐 Debian 11+, Ubuntu 20.04+, Fedora 32+, Arch Linux 等)。
- **内核版本**: 建议 **Linux 5.8+** (最低 5.4，需开启 BTF 支持)。
- **配置要求**: 内核必须开启 `CONFIG_DEBUG_INFO_BTF=y`。
  - 检查方法：`ls /sys/kernel/btf/vmlinux`，如果有文件则说明支持。

## 📦 编译依赖

在编译之前，请确保安装了以下工具：

1. **Go 语言环境** (1.18+)
2. **Clang/LLVM** (用于将 C 代码编译为 BPF 字节码)
3. **bpftool** (用于生成 `vmlinux.h`)
4. **libbpf** (部分发行版需要)

### 安装示例 (Debian/Ubuntu)

Bash

```
sudo apt update
sudo apt install -y clang llvm libbpf-dev bpftool golang make
```

## 🚀 编译步骤

1. **生成内核头文件 (`vmlinux.h`)** 这是 CO-RE 的核心，确保 BPF 程序能识别内核结构体。

   Bash

   ```
   mkdir -p headers
   bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h
   ```

2. **生成 Go 绑定代码** 利用 `bpf2go` 编译 C 代码并生成 Go 结构体。

   Bash

   ```
   go generate ./...
   ```

3. **编译主程序**

   Bash

   ```
   go build -o netmonitor
   ```

*(或者，如果你使用了提供的 Makefile，直接运行 `make` 即可)*

## 📖 使用方法

由于 eBPF 需要特权操作，必须使用 `sudo` 运行。

### 基础用法

启动监控，打印所有捕获到的网络活动：

Bash

```
sudo ./netmonitor
```

### 过滤选项

- **按进程名过滤 (`-comm`)**: 只监控包含特定字符串的命令（如监控 `wget`）。

  Bash

  ```
  sudo ./netmonitor -comm wget
  ```

- **按 PID 过滤 (`-pid`)**: 只监控特定进程 ID。

  Bash

  ```
  sudo ./netmonitor -pid 12345
  ```

### 输出示例

Plaintext

```
TIME                 PID     PROTO DESTINATION               COMMAND LINE
----------------------------------------------------------------------------------------------------
17:14:02.965         3890    UDP   192.168.1.1:53            wget https://example.com/file.zip
17:14:02.980         3890    TCP   93.184.216.34:443         wget https://example.com/file.zip
```

- **UDP 记录**: 通常代表 DNS 解析请求（端口 53）。
- **TCP 记录**: 代表实际的数据连接建立。
- **COMMAND LINE**: 显示完整的执行命令。

## 🧠 原理简述

本项目利用 Linux 内核的 **Tracepoints** 机制：

1. **`sys_enter_connect`**: 拦截 TCP 连接请求。
2. **`sys_enter_sendto`**: 拦截 UDP 数据发送（主要用于捕获 DNS 查询）。
3. **`sys_enter_socket` / `sys_exit_socket`**: 追踪 Socket 文件描述符 (FD) 的创建，以识别该 FD 是 TCP 还是 UDP 类型。
4. **内存读取**: 在内核空间通过 `bpf_probe_read_kernel` 访问当前任务的 `task_struct -> mm_struct -> arg_start/arg_end`，将用户态的命令行参数复制到 RingBuffer 中，传回用户态 Go 程序展示。

## ❓ 常见问题

**Q: 为什么 `wget` 的 DNS 请求显示的命令也是 `wget`？** A: DNS 解析通常是由 `glibc` 库在进程内部完成的。`wget` 调用库函数解析域名，库函数在 `wget` 的进程空间内创建 UDP Socket 并发送数据，因此内核判定该网络行为的发起者就是 `wget` 进程本身。

**Q: 编译时报错 `fatal error: 'vmlinux.h' file not found`？** A: 请确保你执行了“编译步骤”中的第 1 步，成功生成了 `headers/vmlinux.h`。

**Q: 运行时报错 `operation not permitted`？** A: 加载 eBPF 程序需要 `CAP_BPF` 或 `root` 权限，请使用 `sudo` 运行。

## 📄 License

Dual MIT/GPL.
