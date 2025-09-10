package scanner

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"autoscan/pkg/models"
)

// 常用端口预设列表
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 993, 995, 1080, 1433, 1521, 2049,
	3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888,
	9090, 9200, 27017,
}

// PortScanner 执行 TCP 端口扫描
type PortScanner struct {
	Timeout    time.Duration // 连接超时时间
	MaxThreads int           // 最大并发线程数
}

// NewPortScanner 创建新的端口扫描器
func NewPortScanner(timeout time.Duration, maxThreads int) *PortScanner {
	if maxThreads <= 0 {
		maxThreads = 500
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &PortScanner{
		Timeout:    timeout,
		MaxThreads: maxThreads,
	}
}

// ScanHost 扫描单个主机上的所有指定端口
func (ps *PortScanner) ScanHost(host string, ports []int, callback func(models.Port)) []models.Port {
	var (
		results []models.Port
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, ps.MaxThreads) // 信号量控制并发
	)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{} // 获取信号量

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }() // 释放信号量

			if ps.isOpen(host, p) {
				portResult := models.Port{
					Number:   p,
					Protocol: "tcp",
					State:    "open",
				}
				mu.Lock()
				results = append(results, portResult)
				mu.Unlock()

				if callback != nil {
					callback(portResult)
				}
			}
		}(port)
	}

	wg.Wait()

	// 按端口号排序
	sort.Slice(results, func(i, j int) bool {
		return results[i].Number < results[j].Number
	})

	return results
}

// isOpen 使用 TCP Connect 方式检测端口是否开放
func (ps *PortScanner) isOpen(host string, port int) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, ps.Timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ParsePorts 解析端口规格字符串为端口列表
// 支持格式: "80", "80,443", "1-1000", "80,443,8000-9000", "common", "all"
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))

	if spec == "" || spec == "common" {
		return CommonPorts, nil
	}
	if spec == "all" {
		ports := make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
		return ports, nil
	}

	var ports []int
	seen := make(map[int]bool) // 去重

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// 处理端口范围，如 "1-1000"
			rangeParts := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("无效的端口范围起始值: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("无效的端口范围结束值: %s", rangeParts[1])
			}
			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("无效的端口范围: %d-%d", start, end)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			// 处理单个端口
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("无效的端口: %s", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("端口超出范围: %d", p)
			}
			if !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}

	sort.Ints(ports)
	return ports, nil
}
