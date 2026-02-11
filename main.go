package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
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
	targetIP   string
	parsedIP   net.IP // 用于存储解析后的 targetIP
)

func init() {
	flag.IntVar(&targetPID, "pid", 0, "Filter by PID")
	flag.StringVar(&targetComm, "comm", "", "Filter by process name (substring)")
	flag.StringVar(&targetIP, "ip", "", "Filter by destination IP address")
}

func main() {
	flag.Parse()

	// 预先解析 IP 参数，避免在循环中重复解析
	if targetIP != "" {
		parsedIP = net.ParseIP(targetIP)
		if parsedIP == nil {
			log.Fatalf("Invalid IP address format: %s", targetIP)
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// --- 挂载 Tracepoints ---
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

	// 打印表头
	fmt.Printf("%-20s %-7s %-5s %-25s %s\n", "TIME", "PID", "PROTO", "DESTINATION", "COMMAND LINE")
	fmt.Println(strings.Repeat("-", 120))

	// 1. 快照扫描已存在连接 (支持 IP 过滤)
	go snapshotExistingConnections()

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

			// --- IP Filter (内核事件流) ---
			var eventIP net.IP
			if event.Af == 2 { // AF_INET
				eventIP = net.IP(event.Ip[0:4])
			} else { // AF_INET6
				eventIP = net.IP(event.Ip[:])
			}

			// 如果设置了 IP 过滤，且不匹配，则跳过
			if parsedIP != nil && !eventIP.Equal(parsedIP) {
				continue
			}

			// --- PID Filter ---
			if targetPID != 0 && int(event.Pid) != targetPID { continue }

			// --- Command Filter & Processing ---
			cmdBuf := event.Cmd[:]
			cleanCmd := bytes.ReplaceAll(cmdBuf, []byte{0}, []byte(" "))
			finalCmd := string(bytes.TrimSpace(cleanCmd))
			
			if targetComm != "" && !strings.Contains(finalCmd, targetComm) { continue }

			// --- Print ---
			printLine(event, eventIP, finalCmd, false)
		}
	}()

	<-stop
	fmt.Println("\nExiting...")
}

func printLine(e bpfEventT, ip net.IP, cmdline string, isSnapshot bool) {
	port := (e.Port<<8 | e.Port>>8)
	dest := fmt.Sprintf("%s:%d", ip.String(), port)

	proto := "UNK"
	switch e.Proto {
	case 1: proto = "TCP"
	case 2: proto = "UDP"
	}

	ts := time.Now().Format("15:04:05.000")
	suffix := ""
	if isSnapshot {
		suffix = " (EXISTING)"
	}
	fmt.Printf("%-20s %-7d %-5s %-25s %s%s\n", ts, e.Pid, proto, dest, cmdline, suffix)
}

// --- 快照功能 ---

func snapshotExistingConnections() {
	// map[inode] = "IP:Port"
	socketMap := make(map[string]string)
	parseProcNet("/proc/net/tcp", socketMap, false)
	parseProcNet("/proc/net/tcp6", socketMap, true)

	if len(socketMap) == 0 { return }

	procDir, err := os.Open("/proc")
	if err != nil { return }
	defer procDir.Close()

	pids, err := procDir.Readdirnames(-1)
	if err != nil { return }

	for _, pidStr := range pids {
		pid, err := strconv.Atoi(pidStr)
		if err != nil { continue }
		if targetPID != 0 && pid != targetPID { continue }

		fdPath := fmt.Sprintf("/proc/%s/fd", pidStr)
		entries, err := os.ReadDir(fdPath)
		if err != nil { continue }

		cmdline := ""

		for _, entry := range entries {
			link, err := os.Readlink(filepath.Join(fdPath, entry.Name()))
			if err != nil { continue }

			if strings.HasPrefix(link, "socket:[") {
				inode := link[8 : len(link)-1]
				if dest, ok := socketMap[inode]; ok {
					
					// --- IP Filter (快照) ---
					if parsedIP != nil {
						// dest 格式为 "IP:Port"，需要拆分
						host, _, err := net.SplitHostPort(dest)
						if err != nil { continue }
						
						connIP := net.ParseIP(host)
						if !connIP.Equal(parsedIP) {
							continue
						}
					}

					// 获取 Cmdline
					if cmdline == "" {
						cmdline = getProcCmdline(pid)
						if cmdline == "" {
							 commBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%s/comm", pidStr))
							 cmdline = strings.TrimSpace(string(commBytes))
						}
						// Comm Filter
						if targetComm != "" && !strings.Contains(cmdline, targetComm) {
							cmdline = "SKIP"
						}
					}

					if cmdline != "SKIP" {
						ts := time.Now().Format("15:04:05.000")
						fmt.Printf("%-20s %-7d %-5s %-25s %s (EXISTING)\n", 
							ts, pid, "TCP", dest, cmdline)
					}
				}
			}
		}
	}
}

func getProcCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil { return "" }
	res := bytes.ReplaceAll(data, []byte{0}, []byte(" "))
	return string(bytes.TrimSpace(res))
}

func parseProcNet(path string, res map[string]string, isV6 bool) {
	file, err := os.Open(path)
	if err != nil { return }
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() 

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 { continue }

		if fields[3] != "01" { continue } // Only ESTABLISHED

		remAddrHex := fields[2]
		inode := fields[9]

		ipPort, err := hexToIPPort(remAddrHex, isV6)
		if err == nil {
			res[inode] = ipPort
		}
	}
}

func hexToIPPort(hexStr string, isV6 bool) (string, error) {
	parts := strings.Split(hexStr, ":")
	if len(parts) != 2 { return "", fmt.Errorf("invalid format") }

	portVal, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil { return "", err }

	ipHex := parts[0]
	var ip net.IP

	if !isV6 {
		ipBytes, err := hexDecode(ipHex)
		if err != nil || len(ipBytes) != 4 { return "", fmt.Errorf("bad ipv4") }
		ip = net.IP{ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]}
	} else {
		ipBytes, err := hexDecode(ipHex)
		if err != nil || len(ipBytes) != 16 { return "", fmt.Errorf("bad ipv6") }
		// IPv6 in /proc is 4x 32bit Little Endian ints
		ip = make(net.IP, 16)
		for i := 0; i < 4; i++ {
			for j := 0; j < 4; j++ {
				ip[i*4+j] = ipBytes[i*4+3-j]
			}
		}
	}
	return fmt.Sprintf("%s:%d", ip.String(), portVal), nil
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 { return nil, fmt.Errorf("bad length") }
	data := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		val, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil { return nil, err }
		data[i/2] = byte(val)
	}
	return data, nil
}
