# AutoScan

Go + Python 混合漏洞扫描工具，高性能、可扩展。

## 功能

- 🔍 **端口扫描** — TCP Connect 扫描，goroutine 并发，支持全端口/自定义范围
- 🏷️ **服务识别** — Banner Grab + 指纹匹配，识别 SSH/HTTP/MySQL/Redis 等 30+ 服务
- 🌐 **HTTP 探测** — URL 存活检测、Title/Server 提取、页面链接爬取
- 📡 **存活探测** — ICMP Ping 网段扫描，支持 CIDR 和 IP 范围
- 🧩 **Nuclei 模板** — 兼容 Nuclei YAML 模板，可直接使用 7000+ 社区模板
- 🐍 **Python 插件** — JSON-RPC 通信，支持热加载 PoC 插件
- 📊 **彩色输出** — 终端表格展示，JSON 结果导出

## 架构

```
Go 核心引擎（端口扫描/服务识别/HTTP探测/任务调度）
     ↕ JSON-RPC over stdin/stdout
Python 插件层（漏洞检测 PoC / 报告生成）
     +
Nuclei 引擎（YAML 模板解析与执行）
```

## 快速开始

```bash
# 编译
go build -o autoscan ./cmd/autoscan/

# 扫描单个目标
./autoscan scan -t 192.168.1.1

# 全端口扫描
./autoscan scan -t 192.168.1.1 -p 1-65535 --threads 1000

# 网段存活探测 + 端口扫描
./autoscan scan -t 192.168.1.0/24 --ping -p 22,80,443,3389

# 使用 Nuclei 模板
./autoscan nuclei -t http://example.com --templates ./templates

# 使用 Python 插件
./autoscan scan -t 192.168.1.1 --type full --plugins
```

## 内置插件

| 插件 | 检测内容 |
|------|----------|
| sql_injection | SQL 注入（报错/时间盲注） |
| xss_detector | 反射型 XSS |
| directory_traversal | 目录遍历/路径穿越 |
| sensitive_files | 敏感文件泄露（.git/.env/备份等） |

## 内置 Nuclei 模板

| 模板 | 检测内容 |
|------|----------|
| git-config-exposure | Git 配置泄露 |
| env-file-exposure | .env 环境变量泄露 |
| phpinfo-disclosure | PHP 信息泄露 |
| robots-txt | Robots.txt 发现 |
| swagger-api-exposure | Swagger API 文档泄露 |

## 项目结构

```
AutoScan/
├── cmd/autoscan/main.go        # CLI 入口
├── pkg/
│   ├── scanner/                # 扫描引擎
│   │   ├── port.go             #   端口扫描
│   │   ├── service.go          #   服务识别
│   │   ├── http.go             #   HTTP 探测
│   │   └── ping.go             #   存活探测
│   ├── nuclei/                 # Nuclei 模板引擎
│   │   ├── parser.go           #   YAML 解析
│   │   └── executor.go         #   模板执行
│   ├── bridge/python.go        # Go-Python 通信
│   ├── scheduler/scheduler.go  # 任务调度
│   ├── models/types.go         # 数据模型
│   └── output/display.go       # 终端输出
├── plugins/                    # Python 插件
│   ├── runner.py               #   插件运行器
│   ├── base.py                 #   插件基类
│   └── poc/                    #   PoC 插件
└── templates/                  # Nuclei 模板
```

## 依赖

- Go 1.21+
- Python 3.8+（仅插件功能需要）
- `pip install -r plugins/requirements.txt`

## License

MIT
