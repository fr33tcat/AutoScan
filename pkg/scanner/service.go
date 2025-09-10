package scanner

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"autoscan/pkg/models"
)

// ServiceDetector 识别开放端口上运行的服务
type ServiceDetector struct {
	Timeout    time.Duration // 连接超时时间
	MaxThreads int           // 最大并发线程数
}

// NewServiceDetector 创建新的服务识别器
func NewServiceDetector(timeout time.Duration, maxThreads int) *ServiceDetector {
	if maxThreads <= 0 {
		maxThreads = 50
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &ServiceDetector{
		Timeout:    timeout,
		MaxThreads: maxThreads,
	}
}

// DetectServices 对给定的开放端口列表进行服务识别
func (sd *ServiceDetector) DetectServices(host string, ports []models.Port) []models.Port {
	var (
		results []models.Port
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, sd.MaxThreads)
	)

	for _, port := range ports {
		if port.State != "open" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}

		go func(p models.Port) {
			defer wg.Done()
			defer func() { <-sem }()

			service := sd.detectService(host, p.Number)
			p.Service = service

			mu.Lock()
			results = append(results, p)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	return results
}

// detectService 探测单个端口上的服务
func (sd *ServiceDetector) detectService(host string, port int) *models.Service {
	// 第一步：直接抓取 Banner
	banner := sd.grabBanner(host, port)

	// 根据 Banner 匹配服务
	service := sd.matchService(port, banner)

	// 第二步：对无 Banner 响应的服务发送探测包
	if service.Name == "unknown" {
		if probed := sd.probeService(host, port); probed != nil {
			return probed
		}
	}

	return service
}

// grabBanner 连接端口并读取初始响应（Banner信息）
func (sd *ServiceDetector) grabBanner(host string, port int) string {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, sd.Timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(sd.Timeout))

	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	if banner == "" {
		// 尝试读取原始字节
		buf := make([]byte, 1024)
		n, _ := reader.Read(buf)
		banner = string(buf[:n])
	}

	return strings.TrimSpace(banner)
}

// probeService 发送协议探测包以识别服务
func (sd *ServiceDetector) probeService(host string, port int) *models.Service {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// HTTP 协议探测
	conn, err := net.DialTimeout("tcp", addr, sd.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(sd.Timeout))
	conn.SetReadDeadline(time.Now().Add(sd.Timeout))

	// 发送 HTTP 请求
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil
	}

	response := string(buf[:n])

	if strings.HasPrefix(response, "HTTP/") {
		svc := &models.Service{
			Name:  "http",
			Extra: make(map[string]string),
		}
		// 提取 Server 响应头
		for _, line := range strings.Split(response, "\r\n") {
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "server:") {
				svc.Version = strings.TrimSpace(line[7:])
			}
		}
		return svc
	}

	return nil
}

// matchService 根据 Banner 和端口号匹配服务指纹
func (sd *ServiceDetector) matchService(port int, banner string) *models.Service {
	svc := &models.Service{
		Name:   "unknown",
		Banner: banner,
		Extra:  make(map[string]string),
	}

	// 基于 Banner 的正则匹配
	if banner != "" {
		for _, fp := range serviceFingerprints {
			if fp.regex.MatchString(banner) {
				svc.Name = fp.name
				matches := fp.regex.FindStringSubmatch(banner)
				if len(matches) > 1 {
					svc.Version = matches[1]
				}
				return svc
			}
		}
	}

	// 基于端口号的默认匹配（兜底策略）
	if name, ok := defaultPortServices[port]; ok {
		svc.Name = name
	}

	return svc
}

// fingerprint 定义一个服务指纹匹配模式
type fingerprint struct {
	name  string         // 服务名称
	regex *regexp.Regexp // 匹配正则
}

// serviceFingerprints 包含已编译的服务指纹正则表达式
var serviceFingerprints = []fingerprint{
	{name: "ssh", regex: regexp.MustCompile(`(?i)SSH-[\d.]+-(.+)`)},
	{name: "ftp", regex: regexp.MustCompile(`(?i)(\d+)\s.*FTP`)},
	{name: "ftp", regex: regexp.MustCompile(`(?i)^220[- ](.*)`)},
	{name: "smtp", regex: regexp.MustCompile(`(?i)^220.*SMTP|^220.*mail`)},
	{name: "pop3", regex: regexp.MustCompile(`(?i)^\+OK.*POP3|^\+OK (.*)`)},
	{name: "imap", regex: regexp.MustCompile(`(?i)^\* OK.*IMAP`)},
	{name: "mysql", regex: regexp.MustCompile(`(?i)mysql|MariaDB`)},
	{name: "redis", regex: regexp.MustCompile(`(?i)^-ERR|^\$\d+\r\nredis_version:(.+)`)},
	{name: "mongodb", regex: regexp.MustCompile(`(?i)MongoDB|ismaster`)},
	{name: "http", regex: regexp.MustCompile(`(?i)^HTTP/[\d.]+`)},
	{name: "telnet", regex: regexp.MustCompile(`(?i)telnet|login:`)},
}

// defaultPortServices 将常见端口映射到默认服务名
var defaultPortServices = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	443:   "https",
	445:   "microsoft-ds",
	993:   "imaps",
	995:   "pop3s",
	1080:  "socks",
	1433:  "mssql",
	1521:  "oracle",
	2049:  "nfs",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5900:  "vnc",
	6379:  "redis",
	8080:  "http-proxy",
	8443:  "https-alt",
	8888:  "http-alt",
	9090:  "http-alt",
	9200:  "elasticsearch",
	27017: "mongodb",
}
