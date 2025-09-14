package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"autoscan/pkg/models"
)

// 颜色代码常量
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

// 根据漏洞严重等级返回对应颜色
func SeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return ColorPurple
	case "high":
		return ColorRed
	case "medium":
		return ColorYellow
	case "low":
		return ColorBlue
	case "info":
		return ColorCyan
	default:
		return ColorWhite
	}
}

// Banner 打印工具启动横幅
func Banner() {
	banner := `
    ___         __        _____                 
   /   | __  __/ /_____  / ___/_________ _____ 
  / /| |/ / / / __/ __ \ \__ \/ ___/ __ ` + "`" + `/ __ \
 / ___ / /_/ / /_/ /_/ /___/ / /__/ /_/ / / / /
/_/  |_\__,_/\__/\____//____/\___/\__,_/_/ /_/ 
                                        v0.1.0
`
	fmt.Print(ColorCyan + banner + ColorReset)
	fmt.Println(ColorBold + "  Go + Python 混合漏洞扫描工具" + ColorReset)
	fmt.Println(strings.Repeat("─", 52))
	fmt.Println()
}

// PrintPortTable 以表格形式打印端口扫描结果
func PrintPortTable(host string, ports []models.Port) {
	if len(ports) == 0 {
		fmt.Printf("%s[*] %s: 未发现开放端口%s\n", ColorYellow, host, ColorReset)
		return
	}

	fmt.Printf("\n%s[+] %s - 发现 %d 个开放端口:%s\n\n", ColorGreen, host, len(ports), ColorReset)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  %s端口\t协议\t状态\t服务\t版本%s\n", ColorBold, ColorReset)
	fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 60))

	for _, p := range ports {
		serviceName := "unknown"
		serviceVersion := ""
		if p.Service != nil {
			serviceName = p.Service.Name
			serviceVersion = p.Service.Version
		}
		fmt.Fprintf(w, "  %s%d\t%s\t%s\t%s\t%s%s\n",
			ColorGreen, p.Number, p.Protocol, p.State, serviceName, serviceVersion, ColorReset)
	}
	w.Flush()
	fmt.Println()
}

// PrintHTTPInfo 打印 HTTP 探测结果
func PrintHTTPInfo(infos []models.HTTPInfo) {
	if len(infos) == 0 {
		return
	}

	fmt.Printf("\n%s[*] HTTP 探测结果:%s\n\n", ColorCyan, ColorReset)

	for _, info := range infos {
		statusColor := ColorGreen
		if info.StatusCode >= 400 {
			statusColor = ColorRed
		} else if info.StatusCode >= 300 {
			statusColor = ColorYellow
		}

		fmt.Printf("  %s%s%s  [%s%d%s]  [%s]\n",
			ColorBold, info.URL, ColorReset,
			statusColor, info.StatusCode, ColorReset,
			info.Title)

		if info.Server != "" {
			fmt.Printf("    └─ Server: %s\n", info.Server)
		}
	}
	fmt.Println()
}

// PrintVulnerabilities 打印漏洞检测结果
func PrintVulnerabilities(vulns []models.Vulnerability) {
	if len(vulns) == 0 {
		return
	}

	fmt.Printf("\n%s[!] 发现 %d 个漏洞:%s\n\n", ColorRed, len(vulns), ColorReset)

	for _, v := range vulns {
		color := SeverityColor(v.Severity)
		fmt.Printf("  %s[%s]%s %s%s%s\n", color, strings.ToUpper(v.Severity), ColorReset, ColorBold, v.Name, ColorReset)
		fmt.Printf("    描述: %s\n", v.Description)
		if v.URL != "" {
			fmt.Printf("    URL:  %s\n", v.URL)
		}
		if v.CVEID != "" {
			fmt.Printf("    CVE:  %s\n", v.CVEID)
		}
		if v.Solution != "" {
			fmt.Printf("    修复: %s\n", v.Solution)
		}
		fmt.Println()
	}
}

// PrintSummary 打印扫描摘要
func PrintSummary(result *models.ScanResult) {
	duration := result.EndTime.Sub(result.StartTime)

	fmt.Println(strings.Repeat("─", 52))
	fmt.Printf("%s扫描摘要%s\n\n", ColorBold, ColorReset)
	fmt.Printf("  任务ID:    %s\n", result.TaskID)
	fmt.Printf("  扫描耗时:  %v\n", duration.Round(time.Millisecond))
	fmt.Printf("  目标主机:  %d (存活: %d)\n", result.Summary.TotalHosts, result.Summary.AliveHosts)
	fmt.Printf("  开放端口:  %d\n", result.Summary.OpenPorts)
	fmt.Printf("  发现漏洞:  %d\n", result.Summary.Vulns)

	if result.Summary.Vulns > 0 {
		fmt.Printf("\n  漏洞分级:\n")
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if count, ok := result.Summary.VulnsBySeverity[sev]; ok && count > 0 {
				color := SeverityColor(sev)
				fmt.Printf("    %s%-10s%s %d\n", color, strings.ToUpper(sev), ColorReset, count)
			}
		}
	}
	fmt.Println()
}

// SaveJSON 将扫描结果保存为 JSON 文件
func SaveJSON(result *models.ScanResult, filepath string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON 序列化失败: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}

	fmt.Printf("%s[+] 结果已保存至: %s%s\n", ColorGreen, filepath, ColorReset)
	return nil
}
