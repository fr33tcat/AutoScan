package nuclei

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"autoscan/pkg/models"
)

// ExecuteResult 模板执行结果
type ExecuteResult struct {
	TemplateID string                `json:"template_id"`   // 模板 ID
	Matched    bool                  `json:"matched"`       // 是否匹配成功
	Vuln       *models.Vulnerability `json:"vuln,omitempty"` // 漏洞信息（匹配成功时）
	Extracted  map[string]string     `json:"extracted,omitempty"` // 提取的数据
}

// Executor 模板执行引擎
type Executor struct {
	client     *http.Client // HTTP 客户端
	maxThreads int          // 最大并发数
	userAgent  string       // 自定义 User-Agent
}

// NewExecutor 创建新的模板执行器
func NewExecutor(timeout time.Duration, maxThreads int) *Executor {
	if maxThreads <= 0 {
		maxThreads = 25
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}

	return &Executor{
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // 默认不跟随重定向
			},
		},
		maxThreads: maxThreads,
		userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AutoScan/0.1",
	}
}

// ExecuteTemplates 对目标 URL 批量执行模板
func (e *Executor) ExecuteTemplates(baseURL string, templates []*Template, callback func(ExecuteResult)) []ExecuteResult {
	var (
		results []ExecuteResult
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, e.maxThreads)
	)

	for _, tmpl := range templates {
		wg.Add(1)
		sem <- struct{}{}

		go func(t *Template) {
			defer wg.Done()
			defer func() { <-sem }()

			result := e.executeTemplate(baseURL, t)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			if result.Matched && callback != nil {
				callback(result)
			}
		}(tmpl)
	}

	wg.Wait()
	return results
}

// executeTemplate 执行单个模板
func (e *Executor) executeTemplate(baseURL string, tmpl *Template) ExecuteResult {
	result := ExecuteResult{
		TemplateID: tmpl.ID,
		Extracted:  make(map[string]string),
	}

	httpRequests := tmpl.GetHTTPRequests()
	if len(httpRequests) == 0 {
		return result
	}

	for _, httpReq := range httpRequests {
		for _, path := range httpReq.Path {
			// 替换 {{BaseURL}} 变量
			fullURL := strings.ReplaceAll(path, "{{BaseURL}}", strings.TrimRight(baseURL, "/"))
			if !strings.HasPrefix(fullURL, "http") {
				fullURL = strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(fullURL, "/")
			}

			// 构造 HTTP 请求
			method := strings.ToUpper(httpReq.Method)
			if method == "" {
				method = "GET"
			}

			var bodyReader io.Reader
			if httpReq.Body != "" {
				bodyReader = strings.NewReader(httpReq.Body)
			}

			req, err := http.NewRequest(method, fullURL, bodyReader)
			if err != nil {
				continue
			}

			// 设置请求头
			req.Header.Set("User-Agent", e.userAgent)
			for k, v := range httpReq.Headers {
				req.Header.Set(k, v)
			}

			// 配置重定向
			client := e.client
			if httpReq.Redirects {
				maxRedirects := httpReq.MaxRedirects
				if maxRedirects <= 0 {
					maxRedirects = 3
				}
				client = &http.Client{
					Timeout:   e.client.Timeout,
					Transport: e.client.Transport,
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						if len(via) >= maxRedirects {
							return http.ErrUseLastResponse
						}
						return nil
					},
				}
			}

			// 发送请求
			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 最大 2MB
			resp.Body.Close()

			// 构造响应头字符串
			var headerStr strings.Builder
			for k, vals := range resp.Header {
				for _, v := range vals {
					headerStr.WriteString(fmt.Sprintf("%s: %s\n", k, v))
				}
			}

			// 执行匹配器
			matched := e.runMatchers(httpReq, resp.StatusCode, string(body), headerStr.String(), len(body))

			if matched {
				result.Matched = true
				result.Vuln = &models.Vulnerability{
					Name:        tmpl.Info.Name,
					Description: tmpl.Info.Description,
					Severity:    tmpl.Info.Severity,
					URL:         fullURL,
					Solution:    tmpl.Info.Remediation,
					PluginName:  fmt.Sprintf("nuclei:%s", tmpl.ID),
				}
				if len(tmpl.Info.Reference) > 0 {
					result.Vuln.CVEID = tmpl.Info.Reference[0]
				}

				// 执行提取器
				e.runExtractors(httpReq, string(body), headerStr.String(), result.Extracted)

				if httpReq.StopAtFirstMatch {
					return result
				}
			}
		}
	}

	return result
}

// runMatchers 执行所有匹配器
func (e *Executor) runMatchers(httpReq HTTPRequest, statusCode int, body, headers string, bodyLen int) bool {
	if len(httpReq.Matchers) == 0 {
		return false
	}

	condition := strings.ToLower(httpReq.MatchersCondition)
	if condition == "" {
		condition = "or"
	}

	matchResults := make([]bool, len(httpReq.Matchers))

	for i, matcher := range httpReq.Matchers {
		matched := e.runMatcher(matcher, statusCode, body, headers, bodyLen)
		if matcher.Negative {
			matched = !matched
		}
		matchResults[i] = matched
	}

	if condition == "and" {
		// 全部匹配才算成功
		for _, m := range matchResults {
			if !m {
				return false
			}
		}
		return true
	}

	// "or": 任一匹配即成功
	for _, m := range matchResults {
		if m {
			return true
		}
	}
	return false
}

// runMatcher 执行单个匹配器
func (e *Executor) runMatcher(matcher Matcher, statusCode int, body, headers string, bodyLen int) bool {
	// 确定匹配内容
	content := body
	part := strings.ToLower(matcher.Part)
	switch part {
	case "header":
		content = headers
	case "all":
		content = headers + "\n" + body
	}

	switch strings.ToLower(matcher.Type) {
	case "word":
		return e.matchWords(matcher, content)
	case "regex":
		return e.matchRegex(matcher, content)
	case "status":
		return e.matchStatus(matcher, statusCode)
	case "size":
		return e.matchSize(matcher, bodyLen)
	}

	return false
}

// matchWords 关键字匹配
func (e *Executor) matchWords(matcher Matcher, content string) bool {
	condition := strings.ToLower(matcher.Condition)
	if condition == "" {
		condition = "or"
	}

	lower := strings.ToLower(content)

	if condition == "and" {
		for _, word := range matcher.Words {
			if !strings.Contains(lower, strings.ToLower(word)) {
				return false
			}
		}
		return len(matcher.Words) > 0
	}

	// "or"
	for _, word := range matcher.Words {
		if strings.Contains(lower, strings.ToLower(word)) {
			return true
		}
	}
	return false
}

// matchRegex 正则匹配
func (e *Executor) matchRegex(matcher Matcher, content string) bool {
	for _, pattern := range matcher.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(content) {
			return true
		}
	}
	return false
}

// matchStatus 状态码匹配
func (e *Executor) matchStatus(matcher Matcher, statusCode int) bool {
	for _, s := range matcher.Status {
		if s == statusCode {
			return true
		}
	}
	return false
}

// matchSize 响应体大小匹配
func (e *Executor) matchSize(matcher Matcher, bodyLen int) bool {
	for _, s := range matcher.Size {
		if s == bodyLen {
			return true
		}
	}
	return false
}

// runExtractors 执行提取器
func (e *Executor) runExtractors(httpReq HTTPRequest, body, headers string, extracted map[string]string) {
	for _, extractor := range httpReq.Extractors {
		content := body
		if strings.ToLower(extractor.Part) == "header" {
			content = headers
		}

		switch strings.ToLower(extractor.Type) {
		case "regex":
			for _, pattern := range extractor.Regex {
				re, err := regexp.Compile(pattern)
				if err != nil {
					continue
				}
				matches := re.FindStringSubmatch(content)
				group := extractor.Group
				if group < len(matches) {
					name := extractor.Name
					if name == "" {
						name = extractor.Type
					}
					extracted[name] = matches[group]
				}
			}
		case "kval":
			// Key-Value 提取（从响应头提取指定字段）
			for _, line := range strings.Split(headers, "\n") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					val := strings.TrimSpace(parts[1])
					name := extractor.Name
					if name == "" {
						name = key
					}
					if strings.EqualFold(key, name) {
						extracted[name] = val
					}
				}
			}
		}
	}
}
