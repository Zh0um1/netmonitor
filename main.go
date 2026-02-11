package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native -type event_t bpf connect.c -- -I./headers

var (
	targetPID  int
	targetComm string
)

func init() {
	flag.IntVar(&targetPID, "pid", 0, "Filter by PID")
	flag.StringVar(&targetComm, "comm", "", "Filter by process name")
}

func main() {
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// --- Tracepoints ---
	kpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err != nil { log.Fatalf("trace connect: %v", err) }
	defer kpConnect.Close()

	kpSendto, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TraceSendto, nil)
	if err != nil { log.Fatalf("trace sendto: %v", err) }
	defer kpSendto.Close()

	kpSockEntry, err := link.Tracepoint("syscalls", "sys_enter_socket", objs.TraceSocketEntry, nil)
	if err != nil { log.Fatalf("trace socket entry: %v", err) }
	defer kpSockEntry.Close()

	kpSockExit, err := link.Tracepoint("syscalls", "sys_exit_socket", objs.TraceSocketExit, nil)
	if err != nil { log.Fatalf("trace socket exit: %v", err) }
	defer kpSockExit.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil { log.Fatalf("ringbuf: %v", err) }
	defer rd.Close()

	fmt.Printf("%-20s %-7s %-5s %-25s %s\n", "TIME", "PID", "PROTO", "DESTINATION", "COMMAND LINE")
	fmt.Println(strings.Repeat("-", 120))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) { return }
				continue
			}

			var event bpfEventT
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			// --- 处理命令行 ---
			// BPF 发来的是原始字节，包含 \0。例如 [c,u,r,l,\0,e,x,a,m,p,l,e,\0]
			// 我们将有效负载提取出来，并将中间的 \0 替换为空格
			
			// 1. 找到有效数据的截止点（去除尾部全是0的填充区）
			cmdBuf := event.Cmd[:]
			// 简单处理：将所有 \0 替换为空格，然后Trim掉首尾空格
			// 注意：cmdBuf 可能中间有 \0 (分隔参数)，末尾有一大堆 \0 (padding)
			
			// 为了显示美观，我们先转成 byte slice 处理
			cleanCmd := bytes.ReplaceAll(cmdBuf, []byte{0}, []byte(" "))
			finalCmd := string(bytes.TrimSpace(cleanCmd))

			// 如果是回退到 comm 的情况，comm 只有 16 字节且没有空格分隔，逻辑也是兼容的

			// --- Filter ---
			if targetPID != 0 && int(event.Pid) != targetPID { continue }
			if targetComm != "" && !strings.Contains(finalCmd, targetComm) { continue }

			printLine(event, finalCmd)
		}
	}()

	<-stop
	fmt.Println("\nExiting...")
}

func printLine(e bpfEventT, cmdline string) {
	var ip net.IP
	if e.Af == 2 {
		ip = net.IP(e.Ip[0:4])
	} else {
		ip = net.IP(e.Ip[:])
	}
	port := (e.Port<<8 | e.Port>>8)
	dest := fmt.Sprintf("%s:%d", ip.String(), port)

	proto := "UNK"
	switch e.Proto {
	case 1: proto = "TCP"
	case 2: proto = "UDP"
	}

	ts := time.Now().Format("15:04:05.000")
	fmt.Printf("%-20s %-7d %-5s %-25s %s\n", ts, e.Pid, proto, dest, cmdline)
}
