package nuclei

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Template 表示一个 Nuclei 兼容的 YAML 模板
type Template struct {
	ID   string `yaml:"id"`   // 模板唯一标识
	Info Info   `yaml:"info"` // 模板元信息

	// HTTP 请求定义（支持多个请求）
	HTTP []HTTPRequest `yaml:"http,omitempty"`

	// 兼容旧版 Nuclei 的 "requests" 字段
	Requests []HTTPRequest `yaml:"requests,omitempty"`
}

// Info 模板元信息
type Info struct {
	Name        string   `yaml:"name"`                  // 模板名称
	Author      string   `yaml:"author,omitempty"`      // 作者
	Severity    string   `yaml:"severity"`              // 危害等级
	Description string   `yaml:"description,omitempty"` // 描述
	Reference   []string `yaml:"reference,omitempty"`   // 参考链接
	Tags        string   `yaml:"tags,omitempty"`        // 标签（逗号分隔）
	Remediation string   `yaml:"remediation,omitempty"` // 修复建议
}

// HTTPRequest 定义一个 HTTP 请求
type HTTPRequest struct {
	Method            string            `yaml:"method"`                        // 请求方法
	Path              []string          `yaml:"path"`                          // 请求路径（支持 {{BaseURL}} 变量）
	Headers           map[string]string `yaml:"headers,omitempty"`             // 自定义请求头
	Body              string            `yaml:"body,omitempty"`                // 请求体
	Matchers          []Matcher         `yaml:"matchers,omitempty"`            // 匹配器列表
	MatchersCondition string            `yaml:"matchers-condition,omitempty"`  // 匹配条件: "and" 或 "or"（默认 "or"）
	Extractors        []Extractor       `yaml:"extractors,omitempty"`          // 提取器列表
	Redirects         bool              `yaml:"redirects,omitempty"`           // 是否跟随重定向
	MaxRedirects      int               `yaml:"max-redirects,omitempty"`       // 最大重定向次数
	StopAtFirstMatch  bool              `yaml:"stop-at-first-match,omitempty"` // 命中后停止
}

// Matcher 定义匹配规则
type Matcher struct {
	Type      string   `yaml:"type"`                // 匹配类型: word, regex, status, size
	Words     []string `yaml:"words,omitempty"`      // 关键字列表（type=word）
	Regex     []string `yaml:"regex,omitempty"`      // 正则表达式（type=regex）
	Status    []int    `yaml:"status,omitempty"`     // 状态码列表（type=status）
	Size      []int    `yaml:"size,omitempty"`       // 响应体大小（type=size）
	Part      string   `yaml:"part,omitempty"`       // 匹配位置: body, header, all（默认 body）
	Condition string   `yaml:"condition,omitempty"`  // 多关键字条件: "and" 或 "or"（默认 "or"）
	Negative  bool     `yaml:"negative,omitempty"`   // 取反匹配
}

// Extractor 定义提取规则
type Extractor struct {
	Type  string   `yaml:"type"`            // 提取类型: regex, kval
	Name  string   `yaml:"name,omitempty"`  // 提取器名称
	Regex []string `yaml:"regex,omitempty"` // 正则表达式
	Part  string   `yaml:"part,omitempty"`  // 提取位置: body, header
	Group int      `yaml:"group,omitempty"` // 正则分组索引
}

// GetHTTPRequests 返回模板中的所有 HTTP 请求（兼容新旧格式）
func (t *Template) GetHTTPRequests() []HTTPRequest {
	if len(t.HTTP) > 0 {
		return t.HTTP
	}
	return t.Requests
}

// ParseTemplate 从文件解析单个模板
func ParseTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取模板文件失败: %w", err)
	}

	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("解析 YAML 模板失败 (%s): %w", path, err)
	}

	if tmpl.ID == "" {
		return nil, fmt.Errorf("模板缺少 id 字段: %s", path)
	}

	return &tmpl, nil
}

// LoadTemplates 从目录递归加载所有 YAML 模板
func LoadTemplates(dir string) ([]*Template, error) {
	var templates []*Template

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 只处理 .yaml 和 .yml 文件
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		tmpl, err := ParseTemplate(path)
		if err != nil {
			// 跳过解析失败的模板，记录警告
			fmt.Fprintf(os.Stderr, "[WARN] 跳过模板 %s: %v\n", path, err)
			return nil
		}

		templates = append(templates, tmpl)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("扫描模板目录失败: %w", err)
	}

	return templates, nil
}

// FilterTemplates 按标签/严重等级过滤模板
func FilterTemplates(templates []*Template, tags []string, severities []string) []*Template {
	if len(tags) == 0 && len(severities) == 0 {
		return templates
	}

	var filtered []*Template
	for _, tmpl := range templates {
		// 按严重等级过滤
		if len(severities) > 0 {
			matched := false
			for _, s := range severities {
				if strings.EqualFold(tmpl.Info.Severity, s) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// 按标签过滤
		if len(tags) > 0 {
			tmplTags := strings.Split(tmpl.Info.Tags, ",")
			matched := false
			for _, tag := range tags {
				for _, tt := range tmplTags {
					if strings.EqualFold(strings.TrimSpace(tt), strings.TrimSpace(tag)) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				continue
			}
		}

		filtered = append(filtered, tmpl)
	}

	return filtered
}
