package scheduler

import (
	"fmt"
	"sync"
	"time"

	"autoscan/pkg/bridge"
	"autoscan/pkg/models"
	"autoscan/pkg/scanner"
)

// EventType 定义扫描事件类型
type EventType int

const (
	EventPortFound       EventType = iota // 发现开放端口
	EventServiceDetected                  // 识别到服务
	EventHTTPProbed                       // HTTP 探测完成
	EventVulnFound                        // 发现漏洞
	EventHostDone                         // 单主机扫描完成
	EventScanDone                         // 全部扫描完成
	EventError                            // 发生错误
)

// Event 表示一个扫描事件
type Event struct {
	Type    EventType   // 事件类型
	Host    string      // 关联主机
	Data    interface{} // 事件数据
	Message string      // 可读消息
}

// EventHandler 事件回调函数类型
type EventHandler func(Event)

// Scheduler 协调整个扫描流程
type Scheduler struct {
	portScanner     *scanner.PortScanner     // 端口扫描器
	serviceDetector *scanner.ServiceDetector  // 服务识别器
	httpScanner     *scanner.HTTPScanner      // HTTP 扫描器
	pythonBridge    *bridge.PythonBridge      // Python 插件桥接
	config          models.ScanConfig         // 扫描配置
	eventHandler    EventHandler              // 事件处理器
}

// NewScheduler 创建新的扫描调度器
func NewScheduler(config models.ScanConfig, handler EventHandler) *Scheduler {
	timeout := time.Duration(config.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return &Scheduler{
		portScanner:     scanner.NewPortScanner(timeout, config.Threads),
		serviceDetector: scanner.NewServiceDetector(timeout, 50),
		httpScanner:     scanner.NewHTTPScanner(timeout*2, 50),
		config:          config,
		eventHandler:    handler,
	}
}

// SetPythonBridge 设置 Python 插件桥接
func (s *Scheduler) SetPythonBridge(pb *bridge.PythonBridge) {
	s.pythonBridge = pb
}

// emit 发送事件到处理器
func (s *Scheduler) emit(event Event) {
	if s.eventHandler != nil {
		s.eventHandler(event)
	}
}

// Run 执行完整的扫描流水线
func (s *Scheduler) Run() (*models.ScanResult, error) {
	result := &models.ScanResult{
		TaskID:    fmt.Sprintf("scan_%d", time.Now().Unix()),
		StartTime: time.Now(),
		Targets:   s.config.Targets,
		Summary: models.ScanSummary{
			VulnsBySeverity: make(map[string]int),
		},
	}

	// 解析端口范围
	ports, err := scanner.ParsePorts(s.config.Ports)
	if err != nil {
		return nil, fmt.Errorf("解析端口范围失败: %w", err)
	}

	// 并发处理每个目标主机
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)

	for _, target := range s.config.Targets {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()

			hostResult := s.scanHost(host, ports)

			mu.Lock()
			result.Hosts = append(result.Hosts, hostResult)
			result.Summary.TotalHosts++
			if len(hostResult.Ports) > 0 {
				result.Summary.AliveHosts++
			}
			result.Summary.OpenPorts += len(hostResult.Ports)
			result.Summary.Vulns += len(hostResult.Vulnerabilities)
			for _, v := range hostResult.Vulnerabilities {
				result.Summary.VulnsBySeverity[v.Severity]++
			}
			mu.Unlock()

			s.emit(Event{Type: EventHostDone, Host: host, Message: fmt.Sprintf("主机 %s 扫描完成", host)})
		}(target)
	}

	wg.Wait()

	result.EndTime = time.Now()
	s.emit(Event{Type: EventScanDone, Message: "扫描全部完成"})

	return result, nil
}

// scanHost 对单个主机执行完整的扫描流水线
func (s *Scheduler) scanHost(host string, ports []int) models.HostResult {
	hostResult := models.HostResult{
		Host: host,
	}

	// 阶段一：端口扫描
	if s.config.ScanType == "port" || s.config.ScanType == "full" || s.config.ScanType == "" {
		openPorts := s.portScanner.ScanHost(host, ports, func(p models.Port) {
			s.emit(Event{
				Type:    EventPortFound,
				Host:    host,
				Data:    p,
				Message: fmt.Sprintf("[+] %s:%d 开放", host, p.Number),
			})
		})

		// 阶段二：服务识别
		if len(openPorts) > 0 {
			openPorts = s.serviceDetector.DetectServices(host, openPorts)
			for _, p := range openPorts {
				if p.Service != nil && p.Service.Name != "unknown" {
					s.emit(Event{
						Type:    EventServiceDetected,
						Host:    host,
						Data:    p,
						Message: fmt.Sprintf("[*] %s:%d → %s %s", host, p.Number, p.Service.Name, p.Service.Version),
					})
				}
			}
		}

		hostResult.Ports = openPorts
	}

	// 阶段三：HTTP 探测
	if s.config.ScanType == "web" || s.config.ScanType == "full" {
		var urls []string
		if s.config.ScanType == "web" && len(hostResult.Ports) == 0 {
			// Web 模式下如果没做端口扫描，尝试常见 HTTP 端口
			urls = scanner.PortsToHTTPURLs(host, []int{80, 443, 8080, 8443})
		} else {
			urls = scanner.BuildURLs(host, hostResult.Ports)
		}

		if len(urls) > 0 {
			httpInfos := s.httpScanner.ProbeURLs(urls)
			for _, info := range httpInfos {
				s.emit(Event{
					Type:    EventHTTPProbed,
					Host:    host,
					Data:    info,
					Message: fmt.Sprintf("[*] %s [%d] [%s]", info.URL, info.StatusCode, info.Title),
				})
			}
			hostResult.HTTPInfos = httpInfos
		}
	}

	// 阶段四：基于插件的漏洞检测
	if s.config.EnablePlugins && s.pythonBridge != nil {
		for _, p := range hostResult.Ports {
			if p.State != "open" {
				continue
			}
			req := bridge.ScanRequest{
				Host:    host,
				Port:    p.Number,
				Service: p.Service,
				Plugins: s.config.PluginNames,
			}

			// 如果有对应的 HTTP 信息，附加 URL
			for _, info := range hostResult.HTTPInfos {
				req.URL = info.URL
				break
			}

			vulns, err := s.pythonBridge.RunScan(req)
			if err != nil {
				s.emit(Event{
					Type:    EventError,
					Host:    host,
					Message: fmt.Sprintf("插件扫描 %s:%d 出错: %v", host, p.Number, err),
				})
				continue
			}

			for _, v := range vulns {
				s.emit(Event{
					Type:    EventVulnFound,
					Host:    host,
					Data:    v,
					Message: fmt.Sprintf("[!] %s - %s (%s)", v.Name, v.Description, v.Severity),
				})
			}
			hostResult.Vulnerabilities = append(hostResult.Vulnerabilities, vulns...)
		}
	}

	return hostResult
}
