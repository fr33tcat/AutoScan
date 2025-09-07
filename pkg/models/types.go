package models

import "time"

// Target 表示一个扫描目标
type Target struct {
	Host     string   `json:"host"`
	Ports    []int    `json:"ports,omitempty"`
	Protocol string   `json:"protocol,omitempty"` // tcp, udp
	URLs     []string `json:"urls,omitempty"`
}

// Port 表示一个已发现的端口
type Port struct {
	Number   int      `json:"number"`
	Protocol string   `json:"protocol"` // tcp, udp
	State    string   `json:"state"`    // open, closed, filtered
	Service  *Service `json:"service,omitempty"`
}

// Service 表示端口上运行的服务
type Service struct {
	Name    string            `json:"name"`
	Version string            `json:"version,omitempty"`
	Banner  string            `json:"banner,omitempty"`
	Extra   map[string]string `json:"extra,omitempty"`
}

// HTTPInfo 表示 HTTP 响应信息
type HTTPInfo struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Title      string            `json:"title,omitempty"`
	Server     string            `json:"server,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	BodyLength int               `json:"body_length"`
	Links      []string          `json:"links,omitempty"`
}

// Vulnerability 表示一个已发现的漏洞
type Vulnerability struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // critical, high, medium, low, info
	CVEID       string `json:"cve_id,omitempty"`
	URL         string `json:"url,omitempty"`
	Payload     string `json:"payload,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
	Solution    string `json:"solution,omitempty"`
	PluginName  string `json:"plugin_name"`
}

// HostResult 表示单个主机的扫描结果
type HostResult struct {
	Host            string          `json:"host"`
	Ports           []Port          `json:"ports"`
	HTTPInfos       []HTTPInfo      `json:"http_infos,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// ScanResult 表示完整的扫描结果
type ScanResult struct {
	TaskID    string       `json:"task_id"`
	StartTime time.Time   `json:"start_time"`
	EndTime   time.Time   `json:"end_time"`
	Targets   []string    `json:"targets"`
	Hosts     []HostResult `json:"hosts"`
	Summary   ScanSummary  `json:"summary"`
}

// ScanSummary 提供扫描结果的概览统计
type ScanSummary struct {
	TotalHosts      int            `json:"total_hosts"`
	AliveHosts      int            `json:"alive_hosts"`
	OpenPorts       int            `json:"open_ports"`
	Vulns           int            `json:"vulns"`
	VulnsBySeverity map[string]int `json:"vulns_by_severity"`
}

// ScanConfig 保存扫描配置参数
type ScanConfig struct {
	Targets       []string `json:"targets"`
	Ports         string   `json:"ports"`         // 如: "80,443,8080" 或 "1-1000"
	Threads       int      `json:"threads"`
	Timeout       int      `json:"timeout"`       // 秒
	ScanType      string   `json:"scan_type"`     // port, web, full
	EnablePlugins bool     `json:"enable_plugins"`
	PluginNames   []string `json:"plugin_names,omitempty"`
}
