package bridge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"autoscan/pkg/models"
)

// JSONRPCRequest 表示 JSON-RPC 2.0 请求
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

// JSONRPCResponse 表示 JSON-RPC 2.0 响应
type JSONRPCResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *JSONRPCError    `json:"error,omitempty"`
	ID      int64            `json:"id"`
}

// JSONRPCError 表示 JSON-RPC 2.0 错误
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// ScanRequest 发送给 Python 插件运行器的扫描请求
type ScanRequest struct {
	Host    string              `json:"host"`
	Port    int                 `json:"port,omitempty"`
	URL     string              `json:"url,omitempty"`
	Service *models.Service     `json:"service,omitempty"`
	Plugins []string            `json:"plugins,omitempty"` // 为空则执行所有插件
	Extra   map[string]string   `json:"extra,omitempty"`
}

// ScanResponse 从 Python 插件运行器接收的扫描响应
type ScanResponse struct {
	Vulnerabilities []models.Vulnerability `json:"vulnerabilities"`
	PluginName      string                 `json:"plugin_name"`
	Error           string                 `json:"error,omitempty"`
}

// PluginInfo 描述一个已注册的插件
type PluginInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// PythonBridge 管理与 Python 插件运行器的通信
type PythonBridge struct {
	pythonPath string          // Python 解释器路径
	scriptPath string          // 插件运行器脚本路径
	cmd        *exec.Cmd       // 子进程句柄
	stdin      io.WriteCloser  // 标准输入（发送请求）
	stdout     *bufio.Scanner  // 标准输出（接收响应）
	mu         sync.Mutex      // 互斥锁，保证请求-响应的原子性
	requestID  atomic.Int64    // 自增请求ID
	running    bool            // 运行状态
	timeout    time.Duration   // 请求超时时间
}

// NewPythonBridge 创建新的 Python 通信桥
func NewPythonBridge(pythonPath, scriptPath string, timeout time.Duration) *PythonBridge {
	if pythonPath == "" {
		pythonPath = "python"
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &PythonBridge{
		pythonPath: pythonPath,
		scriptPath: scriptPath,
		timeout:    timeout,
	}
}

// Start 启动 Python 插件运行器子进程
func (pb *PythonBridge) Start() error {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if pb.running {
		return nil
	}

	pb.cmd = exec.Command(pb.pythonPath, pb.scriptPath)

	stdin, err := pb.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("创建 stdin 管道失败: %w", err)
	}
	pb.stdin = stdin

	stdout, err := pb.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("创建 stdout 管道失败: %w", err)
	}
	pb.stdout = bufio.NewScanner(stdout)
	pb.stdout.Buffer(make([]byte, 0, 1024*1024), 1024*1024) // 1MB 缓冲区

	if err := pb.cmd.Start(); err != nil {
		return fmt.Errorf("启动 Python 插件运行器失败: %w", err)
	}

	pb.running = true
	return nil
}

// Stop 终止 Python 插件运行器子进程
func (pb *PythonBridge) Stop() error {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if !pb.running {
		return nil
	}

	pb.running = false
	if pb.stdin != nil {
		pb.stdin.Close()
	}
	if pb.cmd != nil && pb.cmd.Process != nil {
		pb.cmd.Process.Kill()
		pb.cmd.Wait()
	}

	return nil
}

// Call 发送 JSON-RPC 请求并等待响应
func (pb *PythonBridge) Call(method string, params interface{}) (*JSONRPCResponse, error) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if !pb.running {
		return nil, fmt.Errorf("Python 通信桥未运行")
	}

	id := pb.requestID.Add(1)
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      id,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}

	// 写入请求（追加换行符作为消息分隔）
	if _, err := fmt.Fprintf(pb.stdin, "%s\n", data); err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}

	// 读取响应
	done := make(chan *JSONRPCResponse, 1)
	errCh := make(chan error, 1)

	go func() {
		if pb.stdout.Scan() {
			var resp JSONRPCResponse
			if err := json.Unmarshal(pb.stdout.Bytes(), &resp); err != nil {
				errCh <- fmt.Errorf("反序列化响应失败: %w", err)
				return
			}
			done <- &resp
		} else {
			errCh <- fmt.Errorf("读取响应失败: %w", pb.stdout.Err())
		}
	}()

	select {
	case resp := <-done:
		return resp, nil
	case err := <-errCh:
		return nil, err
	case <-time.After(pb.timeout):
		return nil, fmt.Errorf("请求超时（%v）", pb.timeout)
	}
}

// ListPlugins 获取可用插件列表
func (pb *PythonBridge) ListPlugins() ([]PluginInfo, error) {
	resp, err := pb.Call("list_plugins", nil)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("插件错误: %s", resp.Error.Message)
	}

	var plugins []PluginInfo
	if err := json.Unmarshal(resp.Result, &plugins); err != nil {
		return nil, fmt.Errorf("解析插件列表失败: %w", err)
	}
	return plugins, nil
}

// RunScan 向插件运行器发送扫描请求
func (pb *PythonBridge) RunScan(req ScanRequest) ([]models.Vulnerability, error) {
	resp, err := pb.Call("scan", req)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("扫描错误: %s", resp.Error.Message)
	}

	var results []ScanResponse
	if err := json.Unmarshal(resp.Result, &results); err != nil {
		return nil, fmt.Errorf("解析扫描结果失败: %w", err)
	}

	var vulns []models.Vulnerability
	for _, r := range results {
		vulns = append(vulns, r.Vulnerabilities...)
	}
	return vulns, nil
}
