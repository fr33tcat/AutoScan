package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"autoscan/pkg/models"
)

// HTTPScanner 执行 HTTP 探测与信息提取
type HTTPScanner struct {
	Client     *http.Client // HTTP 客户端
	MaxThreads int          // 最大并发线程数
	UserAgent  string       // 自定义 User-Agent
}

// NewHTTPScanner 创建新的 HTTP 扫描器
func NewHTTPScanner(timeout time.Duration, maxThreads int) *HTTPScanner {
	if maxThreads <= 0 {
		maxThreads = 50
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 跳过 TLS 证书验证
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}

	return &HTTPScanner{
		Client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("重定向次数过多")
				}
				return nil
			},
		},
		MaxThreads: maxThreads,
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}
}

// ProbeURLs 批量探测 URL 列表，返回 HTTP 信息
func (hs *HTTPScanner) ProbeURLs(urls []string) []models.HTTPInfo {
	var (
		results []models.HTTPInfo
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, hs.MaxThreads)
	)

	for _, url := range urls {
		wg.Add(1)
		sem <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			if info := hs.probeURL(u); info != nil {
				mu.Lock()
				results = append(results, *info)
				mu.Unlock()
			}
		}(url)
	}

	wg.Wait()
	return results
}

// BuildURLs 根据主机和开放端口生成 HTTP/HTTPS URL
func BuildURLs(host string, ports []models.Port) []string {
	var urls []string
	httpPorts := map[int]bool{80: true, 8080: true, 8888: true, 9090: true}
	httpsPorts := map[int]bool{443: true, 8443: true}

	for _, p := range ports {
		if p.State != "open" {
			continue
		}
		svcName := ""
		if p.Service != nil {
			svcName = p.Service.Name
		}

		if httpsPorts[p.Number] || svcName == "https" {
			urls = append(urls, fmt.Sprintf("https://%s:%d", host, p.Number))
		} else if httpPorts[p.Number] || svcName == "http" || svcName == "http-proxy" || svcName == "http-alt" {
			urls = append(urls, fmt.Sprintf("http://%s:%d", host, p.Number))
		} else {
			// 未知服务默认尝试 HTTP
			urls = append(urls, fmt.Sprintf("http://%s:%d", host, p.Number))
		}
	}

	return urls
}

// probeURL 发送 HTTP 请求并提取响应信息
func (hs *HTTPScanner) probeURL(url string) *models.HTTPInfo {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", hs.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	resp, err := hs.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// 读取响应体（限制最大 1MB）
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		body = []byte{}
	}

	info := &models.HTTPInfo{
		URL:        url,
		StatusCode: resp.StatusCode,
		BodyLength: len(body),
		Headers:    make(map[string]string),
	}

	// 提取响应头
	for key := range resp.Header {
		info.Headers[key] = resp.Header.Get(key)
	}

	// 提取 Server 头
	if server := resp.Header.Get("Server"); server != "" {
		info.Server = server
	}

	// 提取页面标题
	info.Title = extractTitle(string(body))

	// 提取页面链接
	info.Links = extractLinks(string(body), url)

	return info
}

// 页面标题提取正则
var titleRegex = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// extractTitle 从 HTML 中提取页面标题
func extractTitle(body string) string {
	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// 清理多余空白
		title = strings.Join(strings.Fields(title), " ")
		if len(title) > 200 {
			title = title[:200] + "..."
		}
		return title
	}
	return ""
}

// 链接提取正则
var linkRegex = regexp.MustCompile(`(?i)href=["']([^"']+)["']`)

// extractLinks 从 HTML 中提取链接
func extractLinks(body, baseURL string) []string {
	matches := linkRegex.FindAllStringSubmatch(body, 100)
	seen := make(map[string]bool)
	var links []string

	for _, match := range matches {
		if len(match) > 1 {
			link := match[1]
			// 跳过锚点、JavaScript、邮件链接
			if strings.HasPrefix(link, "#") || strings.HasPrefix(link, "javascript:") || strings.HasPrefix(link, "mailto:") {
				continue
			}
			// 处理相对路径
			if !strings.HasPrefix(link, "http") {
				link = strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(link, "/")
			}
			if !seen[link] {
				seen[link] = true
				links = append(links, link)
			}
		}
	}

	return links
}

// PortsToHTTPURLs 将主机和端口列表转换为 HTTP URL（用于 HTTP 探测）
func PortsToHTTPURLs(host string, ports []int) []string {
	var urls []string
	for _, p := range ports {
		scheme := "http"
		if p == 443 || p == 8443 {
			scheme = "https"
		}
		urls = append(urls, fmt.Sprintf("%s://%s:%s", scheme, host, strconv.Itoa(p)))
	}
	return urls
}
