package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// HostDiscovery 负责主机存活探测
type HostDiscovery struct {
	Timeout    time.Duration // 探测超时时间
	MaxThreads int           // 最大并发数
}

// NewHostDiscovery 创建新的主机存活探测器
func NewHostDiscovery(timeout time.Duration, maxThreads int) *HostDiscovery {
	if maxThreads <= 0 {
		maxThreads = 200
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &HostDiscovery{
		Timeout:    timeout,
		MaxThreads: maxThreads,
	}
}

// AliveHost 表示一个存活主机
type AliveHost struct {
	IP     string `json:"ip"`
	Method string `json:"method"` // icmp, tcp
	RTT    string `json:"rtt"`    // 往返时间
}

// Discover 对给定的 IP 列表进行存活探测
// 仅使用系统 ping 命令（最准确，兼容性最好）
func (hd *HostDiscovery) Discover(hosts []string, callback func(AliveHost)) []AliveHost {
	var (
		results []AliveHost
		mu      sync.Mutex
		wg      sync.WaitGroup
		// ping 命令并发限制为 30，避免进程过多导致系统资源不足
		sem     = make(chan struct{}, 30)
	)

	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}

		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			// 使用系统 ping 命令探测（最准确，无需管理员权限）
			if rtt, ok := hd.systemPing(h); ok {
				alive := AliveHost{IP: h, Method: "icmp", RTT: rtt}
				mu.Lock()
				results = append(results, alive)
				mu.Unlock()
				if callback != nil {
					callback(alive)
				}
			}
			// 不再回退到 TCP ping —— 网关/NAT 环境下 TCP 连接会产生大量误报
		}(host)
	}

	wg.Wait()

	// 按 IP 排序
	sort.Slice(results, func(i, j int) bool {
		return results[i].IP < results[j].IP
	})

	return results
}

// systemPing 使用系统 ping 命令探测（无需管理员权限，Windows 兼容）
func (hd *HostDiscovery) systemPing(host string) (string, bool) {
	timeoutMs := int(hd.Timeout.Milliseconds())
	if timeoutMs <= 0 {
		timeoutMs = 2000
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// Windows: ping -n 1 -w 超时(毫秒) 目标
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", timeoutMs), host)
	} else {
		// Linux/macOS: ping -c 1 -W 超时(秒) 目标
		timeoutSec := int(hd.Timeout.Seconds())
		if timeoutSec <= 0 {
			timeoutSec = 2
		}
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutSec), host)
	}

	start := time.Now()
	output, err := cmd.CombinedOutput()
	rtt := time.Since(start)

	if err != nil {
		return "", false
	}

	// 检查输出中是否包含成功标志
	outputStr := string(output)
	if strings.Contains(outputStr, "TTL=") || strings.Contains(outputStr, "ttl=") ||
		strings.Contains(outputStr, "time=") || strings.Contains(outputStr, "时间=") {
		return rtt.Round(time.Millisecond).String(), true
	}

	return "", false
}

// icmpPing 使用原始 ICMP 套接字探测（Windows 需要管理员权限）
func (hd *HostDiscovery) icmpPing(host string) (string, bool) {
	conn, err := net.DialTimeout("ip4:icmp", host, hd.Timeout)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(hd.Timeout))

	// 构造 ICMP Echo Request
	msg := makeICMPEchoRequest(1, 1)

	start := time.Now()
	_, err = conn.Write(msg)
	if err != nil {
		return "", false
	}

	// 读取响应
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return "", false
	}

	rtt := time.Since(start)

	// 验证 ICMP Echo Reply（type=0, code=0）
	if n >= 20 {
		icmpData := buf[20:n] // 跳过 IP 头
		if len(icmpData) >= 4 && icmpData[0] == 0 {
			return rtt.Round(time.Microsecond).String(), true
		}
	}

	// 某些系统返回的数据没有 IP 头
	if n >= 4 && buf[0] == 0 {
		return rtt.Round(time.Microsecond).String(), true
	}

	return "", false
}

// tcpPing 使用 TCP 连接探测（仅成功建立连接才算存活）
// 注意: 不再把 "connection refused" 当作存活，因为网关可能代替不存在的主机返回 RST
func (hd *HostDiscovery) tcpPing(host string) (string, bool) {
	// 只尝试最常见的端口
	ports := []int{80, 443, 22}

	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", host, port)
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, hd.Timeout)
		if err == nil {
			rtt := time.Since(start)
			conn.Close()
			return rtt.Round(time.Microsecond).String(), true
		}
		// 不再将 "connection refused" 视为存活
		// 网关/防火墙可能代替不存在的主机返回 RST，导致大量误报
	}

	return "", false
}

// makeICMPEchoRequest 构造 ICMP Echo Request 数据包
func makeICMPEchoRequest(id, seq int) []byte {
	msg := make([]byte, 8)
	msg[0] = 8 // type: Echo Request
	msg[1] = 0 // code: 0
	msg[2] = 0 // checksum (高位)
	msg[3] = 0 // checksum (低位)
	msg[4] = byte(id >> 8)
	msg[5] = byte(id)
	msg[6] = byte(seq >> 8)
	msg[7] = byte(seq)

	// 计算校验和
	cs := checksum(msg)
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs)

	return msg
}

// checksum 计算 ICMP 校验和
func checksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	for i := 0; i+1 < length; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if length%2 != 0 {
		sum += uint32(data[length-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16

	return ^uint16(sum)
}

// ParseCIDR 解析 CIDR 网段为 IP 列表
// 支持格式: "192.168.1.0/24", "192.168.1.1", "192.168.1.1-192.168.1.10"
func ParseCIDR(input string) ([]string, error) {
	input = strings.TrimSpace(input)

	// 单个 IP
	if net.ParseIP(input) != nil {
		return []string{input}, nil
	}

	// CIDR 格式
	if strings.Contains(input, "/") {
		ip, ipNet, err := net.ParseCIDR(input)
		if err != nil {
			return nil, fmt.Errorf("无效的 CIDR 地址: %s", input)
		}

		var ips []string
		for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
			ips = append(ips, ip.String())
		}

		// 去掉网络地址和广播地址
		if len(ips) > 2 {
			ips = ips[1 : len(ips)-1]
		}

		return ips, nil
	}

	// IP 范围格式: "192.168.1.1-192.168.1.10"
	if strings.Contains(input, "-") {
		parts := strings.SplitN(input, "-", 2)
		startIP := net.ParseIP(strings.TrimSpace(parts[0]))
		endIP := net.ParseIP(strings.TrimSpace(parts[1]))

		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("无效的 IP 范围: %s", input)
		}

		var ips []string
		for ip := startIP; !ip.Equal(endIP); incrementIP(ip) {
			ips = append(ips, ip.String())
		}
		ips = append(ips, endIP.String())

		return ips, nil
	}

	// 域名，直接返回
	return []string{input}, nil
}

// incrementIP 将 IP 地址加 1
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ExpandTargets 将目标列表中的 CIDR 和范围展开为完整 IP 列表
func ExpandTargets(targets []string) ([]string, error) {
	var expanded []string
	seen := make(map[string]bool)

	for _, t := range targets {
		ips, err := ParseCIDR(t)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if !seen[ip] {
				seen[ip] = true
				expanded = append(expanded, ip)
			}
		}
	}

	return expanded, nil
}
