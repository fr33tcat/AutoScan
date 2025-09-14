package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"autoscan/pkg/bridge"
	"autoscan/pkg/models"
	"autoscan/pkg/nuclei"
	"autoscan/pkg/output"
	"autoscan/pkg/scanner"
	"autoscan/pkg/scheduler"

	"github.com/spf13/cobra"
)

var version = "0.2.0"

func main() {
	rootCmd := &cobra.Command{
		Use:   "autoscan",
		Short: "AutoScan - Go + Python 混合漏洞扫描工具",
		Long:  "AutoScan 是一款高性能、可扩展的漏洞扫描工具。\nGo 引擎负责端口扫描、服务识别和 HTTP 探测，Python 插件和 Nuclei 模板负责漏洞检测。",
	}

	// 添加子命令
	rootCmd.AddCommand(
		newScanCmd(),
		newNucleiCmd(),
		newVersionCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// newScanCmd 创建 scan 子命令
func newScanCmd() *cobra.Command {
	var (
		targets      string
		ports        string
		threads      int
		timeout      int
		scanType     string
		outputFile   string
		usePlugins   bool
		pluginDir    string
		pythonPath   string
		templateDir  string
		templateTags string
		enablePing   bool
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "执行漏洞扫描",
		Long:  "对目标主机进行端口扫描、服务识别、HTTP 探测和漏洞检测。",
		Example: `  # 扫描单个目标（常用端口）
  autoscan scan -t 192.168.1.1

  # 扫描指定端口范围
  autoscan scan -t 192.168.1.1 -p 1-1000

  # 扫描多个目标
  autoscan scan -t 192.168.1.1,192.168.1.2

  # 全量扫描（含漏洞检测插件）
  autoscan scan -t 192.168.1.1 --type full --plugins

  # 使用 Nuclei 模板扫描
  autoscan scan -t example.com --type web --templates ./templates

  # 指定线程数和超时时间
  autoscan scan -t 192.168.1.0/24 -p 80,443 --threads 1000 --timeout 3`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// 打印横幅
			output.Banner()

			// 解析目标列表
			targetList := parseTargets(targets)
			if len(targetList) == 0 {
				return fmt.Errorf("请指定扫描目标，使用 -t 参数")
			}

			// 展开 CIDR 和 IP 范围
			expandedTargets, err := scanner.ExpandTargets(targetList)
			if err != nil {
				return fmt.Errorf("解析目标失败: %w", err)
			}
			targetList = expandedTargets

			fmt.Printf("%s[*] 扫描目标: %d 个主机%s\n", output.ColorCyan, len(targetList), output.ColorReset)
			fmt.Printf("%s[*] 端口范围: %s%s\n", output.ColorCyan, ports, output.ColorReset)
			fmt.Printf("%s[*] 扫描类型: %s%s\n", output.ColorCyan, scanType, output.ColorReset)
			fmt.Printf("%s[*] 并发线程: %d%s\n", output.ColorCyan, threads, output.ColorReset)

			// ICMP/TCP 存活探测
			if enablePing && len(targetList) > 1 {
				fmt.Printf("%s[*] 正在进行存活探测...%s\n\n", output.ColorCyan, output.ColorReset)
				hd := scanner.NewHostDiscovery(time.Duration(timeout)*time.Second, 200)
				aliveHosts := hd.Discover(targetList, func(h scanner.AliveHost) {
					fmt.Printf("  %s[+] %s 存活 (%s, %s)%s\n",
						output.ColorGreen, h.IP, h.Method, h.RTT, output.ColorReset)
				})

				fmt.Printf("\n%s[*] 存活主机: %d / %d%s\n\n",
					output.ColorCyan, len(aliveHosts), len(targetList), output.ColorReset)

				// 只扫描存活主机
				targetList = nil
				for _, h := range aliveHosts {
					targetList = append(targetList, h.IP)
				}

				if len(targetList) == 0 {
					fmt.Printf("%s[!] 未发现存活主机%s\n", output.ColorYellow, output.ColorReset)
					return nil
				}
			}
			fmt.Println()

			// 构建扫描配置
			config := models.ScanConfig{
				Targets:       targetList,
				Ports:         ports,
				Threads:       threads,
				Timeout:       timeout,
				ScanType:      scanType,
				EnablePlugins: usePlugins,
			}

			// 创建事件处理器（实时输出扫描进度）
			handler := func(event scheduler.Event) {
				switch event.Type {
				case scheduler.EventPortFound:
					fmt.Printf("  %s%s%s\n", output.ColorGreen, event.Message, output.ColorReset)
				case scheduler.EventServiceDetected:
					fmt.Printf("  %s%s%s\n", output.ColorCyan, event.Message, output.ColorReset)
				case scheduler.EventHTTPProbed:
					fmt.Printf("  %s%s%s\n", output.ColorBlue, event.Message, output.ColorReset)
				case scheduler.EventVulnFound:
					fmt.Printf("  %s%s%s\n", output.ColorRed, event.Message, output.ColorReset)
				case scheduler.EventError:
					fmt.Printf("  %s[ERROR] %s%s\n", output.ColorRed, event.Message, output.ColorReset)
				case scheduler.EventHostDone:
					// 单主机完成，静默处理
				case scheduler.EventScanDone:
					// 全部扫描完成
				}
			}

			// 创建调度器并执行扫描
			sched := scheduler.NewScheduler(config, handler)

			// 如果启用插件，初始化 Python 桥接
			if usePlugins {
				scriptPath := filepath.Join(pluginDir, "runner.py")
				pb := bridge.NewPythonBridge(pythonPath, scriptPath, 30*time.Second)
				if err := pb.Start(); err != nil {
					fmt.Printf("%s[!] 插件系统启动失败: %v（将跳过漏洞检测）%s\n", output.ColorYellow, err, output.ColorReset)
				} else {
					defer pb.Stop()
					sched.SetPythonBridge(pb)
					fmt.Printf("%s[+] 插件系统已启动%s\n\n", output.ColorGreen, output.ColorReset)
				}
			}

			// 执行扫描
			result, err := sched.Run()
			if err != nil {
				return fmt.Errorf("扫描执行失败: %w", err)
			}

			// 如果指定了模板目录，执行 Nuclei 模板扫描
			if templateDir != "" {
				fmt.Printf("\n%s[*] 正在加载 Nuclei 模板: %s%s\n", output.ColorCyan, templateDir, output.ColorReset)

				templates, err := nuclei.LoadTemplates(templateDir)
				if err != nil {
					fmt.Printf("%s[!] 加载模板失败: %v%s\n", output.ColorYellow, err, output.ColorReset)
				} else {
					// 按标签过滤
					if templateTags != "" {
						tags := strings.Split(templateTags, ",")
						templates = nuclei.FilterTemplates(templates, tags, nil)
					}

					fmt.Printf("%s[+] 已加载 %d 个模板%s\n\n", output.ColorGreen, len(templates), output.ColorReset)

					executor := nuclei.NewExecutor(time.Duration(timeout)*time.Second, threads/10+1)

					// 对每个有 HTTP 信息的主机执行模板
					for _, host := range result.Hosts {
						for _, info := range host.HTTPInfos {
							results := executor.ExecuteTemplates(info.URL, templates, func(r nuclei.ExecuteResult) {
								if r.Vuln != nil {
									color := output.SeverityColor(r.Vuln.Severity)
									fmt.Printf("  %s[nuclei] [%s] [%s] %s%s\n",
										color, r.TemplateID, r.Vuln.Severity, r.Vuln.URL, output.ColorReset)
								}
							})

							// 将模板结果合并到扫描结果
							for _, r := range results {
								if r.Matched && r.Vuln != nil {
									result.Summary.Vulns++
									result.Summary.VulnsBySeverity[r.Vuln.Severity]++
									// 查找并更新对应的 host
									for i := range result.Hosts {
										if result.Hosts[i].Host == host.Host {
											result.Hosts[i].Vulnerabilities = append(result.Hosts[i].Vulnerabilities, *r.Vuln)
										}
									}
								}
							}
						}
					}
				}
			}

			// 打印详细结果
			for _, host := range result.Hosts {
				output.PrintPortTable(host.Host, host.Ports)
				output.PrintHTTPInfo(host.HTTPInfos)
				output.PrintVulnerabilities(host.Vulnerabilities)
			}

			// 打印扫描摘要
			output.PrintSummary(result)

			// 保存结果
			if outputFile != "" {
				if err := output.SaveJSON(result, outputFile); err != nil {
					return err
				}
			}

			return nil
		},
	}

	// 命令行参数定义
	cmd.Flags().StringVarP(&targets, "target", "t", "", "扫描目标（IP/域名/CIDR，多个用逗号分隔）")
	cmd.Flags().StringVarP(&ports, "port", "p", "common", "端口范围（如: 80,443 / 1-1000 / common / all）")
	cmd.Flags().IntVar(&threads, "threads", 500, "并发线程数")
	cmd.Flags().IntVar(&timeout, "timeout", 5, "连接超时时间（秒）")
	cmd.Flags().StringVar(&scanType, "type", "full", "扫描类型（port/web/full）")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "结果输出文件路径（JSON 格式）")
	cmd.Flags().BoolVar(&usePlugins, "plugins", false, "启用 Python 漏洞检测插件")
	cmd.Flags().StringVar(&pluginDir, "plugin-dir", "plugins", "插件目录路径")
	cmd.Flags().StringVar(&pythonPath, "python", "python", "Python 解释器路径")
	cmd.Flags().StringVar(&templateDir, "templates", "", "Nuclei YAML 模板目录路径")
	cmd.Flags().StringVar(&templateTags, "tags", "", "按标签过滤模板（逗号分隔）")
	cmd.Flags().BoolVar(&enablePing, "ping", false, "扫描前先进行 ICMP/TCP 存活探测")

	cmd.MarkFlagRequired("target")

	return cmd
}

// newNucleiCmd 创建 nuclei 子命令（独立的模板扫描模式）
func newNucleiCmd() *cobra.Command {
	var (
		targets      string
		templateDir  string
		templateTags string
		severity     string
		threads      int
		timeout      int
		outputFile   string
	)

	cmd := &cobra.Command{
		Use:   "nuclei",
		Short: "使用 Nuclei 模板执行漏洞扫描",
		Long:  "加载并执行 Nuclei 兼容的 YAML 模板，对目标 URL 进行漏洞检测。\n支持 Nuclei 官方模板库。",
		Example: `  # 使用内置模板扫描
  autoscan nuclei -t http://example.com --templates ./templates

  # 使用 Nuclei 官方模板库
  autoscan nuclei -t http://example.com --templates ~/nuclei-templates

  # 按标签过滤模板
  autoscan nuclei -t http://example.com --templates ./templates --tags exposure,config

  # 按严重等级过滤
  autoscan nuclei -t http://example.com --templates ./templates --severity critical,high`,
		RunE: func(cmd *cobra.Command, args []string) error {
			output.Banner()

			targetList := parseTargets(targets)
			if len(targetList) == 0 {
				return fmt.Errorf("请指定目标 URL，使用 -t 参数")
			}

			if templateDir == "" {
				return fmt.Errorf("请指定模板目录，使用 --templates 参数")
			}

			// 加载模板
			fmt.Printf("%s[*] 正在加载模板: %s%s\n", output.ColorCyan, templateDir, output.ColorReset)
			templates, err := nuclei.LoadTemplates(templateDir)
			if err != nil {
				return fmt.Errorf("加载模板失败: %w", err)
			}

			// 过滤模板
			var tags, severities []string
			if templateTags != "" {
				tags = strings.Split(templateTags, ",")
			}
			if severity != "" {
				severities = strings.Split(severity, ",")
			}
			if len(tags) > 0 || len(severities) > 0 {
				templates = nuclei.FilterTemplates(templates, tags, severities)
			}

			fmt.Printf("%s[+] 已加载 %d 个模板%s\n", output.ColorGreen, len(templates), output.ColorReset)
			fmt.Printf("%s[*] 扫描目标: %s%s\n\n", output.ColorCyan, strings.Join(targetList, ", "), output.ColorReset)

			executor := nuclei.NewExecutor(time.Duration(timeout)*time.Second, threads)

			totalVulns := 0
			var allVulns []models.Vulnerability

			for _, target := range targetList {
				results := executor.ExecuteTemplates(target, templates, func(r nuclei.ExecuteResult) {
					if r.Vuln != nil {
						color := output.SeverityColor(r.Vuln.Severity)
						fmt.Printf("  %s[%s] [%s] %s%s\n",
							color, r.TemplateID, r.Vuln.Severity, r.Vuln.URL, output.ColorReset)
					}
				})

				for _, r := range results {
					if r.Matched && r.Vuln != nil {
						totalVulns++
						allVulns = append(allVulns, *r.Vuln)
					}
				}
			}

			// 打印汇总
			fmt.Println()
			fmt.Println(strings.Repeat("─", 52))
			fmt.Printf("%s模板扫描完成%s\n\n", output.ColorBold, output.ColorReset)
			fmt.Printf("  模板数量:  %d\n", len(templates))
			fmt.Printf("  扫描目标:  %d\n", len(targetList))
			fmt.Printf("  发现漏洞:  %d\n", totalVulns)
			fmt.Println()

			if len(allVulns) > 0 {
				output.PrintVulnerabilities(allVulns)
			}

			// 保存结果
			if outputFile != "" {
				result := &models.ScanResult{
					TaskID:    fmt.Sprintf("nuclei_%d", time.Now().Unix()),
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Targets:   targetList,
					Hosts: []models.HostResult{{
						Host:            targetList[0],
						Vulnerabilities: allVulns,
					}},
					Summary: models.ScanSummary{
						TotalHosts:      len(targetList),
						Vulns:           totalVulns,
						VulnsBySeverity: make(map[string]int),
					},
				}
				for _, v := range allVulns {
					result.Summary.VulnsBySeverity[v.Severity]++
				}
				if err := output.SaveJSON(result, outputFile); err != nil {
					return err
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&targets, "target", "t", "", "目标 URL（多个用逗号分隔）")
	cmd.Flags().StringVar(&templateDir, "templates", "", "Nuclei 模板目录路径")
	cmd.Flags().StringVar(&templateTags, "tags", "", "按标签过滤（逗号分隔）")
	cmd.Flags().StringVar(&severity, "severity", "", "按严重等级过滤（critical,high,medium,low,info）")
	cmd.Flags().IntVar(&threads, "threads", 25, "并发线程数")
	cmd.Flags().IntVar(&timeout, "timeout", 10, "请求超时时间（秒）")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "结果输出文件路径（JSON 格式）")

	cmd.MarkFlagRequired("target")
	cmd.MarkFlagRequired("templates")

	return cmd
}

// newVersionCmd 创建 version 子命令
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "显示版本信息",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("AutoScan v%s\n", version)
		},
	}
}

// parseTargets 解析目标字符串为目标列表
func parseTargets(input string) []string {
	var targets []string
	parts := strings.Split(input, ",")
	for _, part := range parts {
		t := strings.TrimSpace(part)
		if t != "" {
			targets = append(targets, t)
		}
	}
	return targets
}
