"""
AutoScan 插件运行器

常驻进程，通过 stdin/stdout 接收 Go 引擎的 JSON-RPC 请求，
调度插件执行漏洞检测并返回结果。
"""

import sys
import json
import importlib
import os
import traceback
from pathlib import Path
from typing import Dict, List

from base import BasePlugin, Target, VulnResult


class PluginRunner:
    """插件运行器：管理插件的发现、加载和执行"""

    def __init__(self):
        self.plugins: Dict[str, BasePlugin] = {}
        self._load_plugins()

    def _load_plugins(self):
        """自动发现并加载 poc/ 目录下的所有插件"""
        poc_dir = Path(__file__).parent / "poc"
        if not poc_dir.exists():
            return

        # 将 poc 目录加入 Python 路径
        sys.path.insert(0, str(poc_dir.parent))

        for file in poc_dir.glob("*.py"):
            if file.name.startswith("_"):
                continue

            module_name = f"poc.{file.stem}"
            try:
                module = importlib.import_module(module_name)
                # 查找模块中所有继承 BasePlugin 的类
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) 
                        and issubclass(attr, BasePlugin) 
                        and attr is not BasePlugin
                        and attr.enabled):
                        plugin = attr()
                        self.plugins[plugin.name] = plugin
            except Exception as e:
                self._log(f"加载插件 {module_name} 失败: {e}")

        self._log(f"已加载 {len(self.plugins)} 个插件: {list(self.plugins.keys())}")

    def _log(self, message: str):
        """输出日志到 stderr（避免干扰 JSON-RPC 通信）"""
        print(f"[PluginRunner] {message}", file=sys.stderr, flush=True)

    def handle_request(self, request: dict) -> dict:
        """处理单个 JSON-RPC 请求"""
        method = request.get("method", "")
        params = request.get("params", {})
        req_id = request.get("id", 0)

        try:
            if method == "list_plugins":
                result = self._list_plugins()
            elif method == "scan":
                result = self._run_scan(params)
            elif method == "ping":
                result = "pong"
            else:
                return self._error_response(req_id, -32601, f"未知方法: {method}")

            return self._success_response(req_id, result)

        except Exception as e:
            self._log(f"处理请求出错: {traceback.format_exc()}")
            return self._error_response(req_id, -32000, str(e))

    def _list_plugins(self) -> list:
        """返回所有已注册插件的信息"""
        return [plugin.info() for plugin in self.plugins.values()]

    def _run_scan(self, params: dict) -> list:
        """执行漏洞扫描"""
        # 构造目标对象
        target = Target(
            host=params.get("host", ""),
            port=params.get("port", 0),
            url=params.get("url", ""),
            service=params.get("service"),
            extra=params.get("extra", {}),
        )

        # 确定要执行的插件
        plugin_names = params.get("plugins", [])
        if plugin_names:
            plugins_to_run = {
                name: p for name, p in self.plugins.items() 
                if name in plugin_names
            }
        else:
            plugins_to_run = self.plugins

        # 执行每个插件
        results = []
        for name, plugin in plugins_to_run.items():
            try:
                vulns = plugin.check(target)
                results.append({
                    "plugin_name": name,
                    "vulnerabilities": [v.to_dict() for v in vulns],
                })
            except Exception as e:
                self._log(f"插件 {name} 执行出错: {e}")
                results.append({
                    "plugin_name": name,
                    "vulnerabilities": [],
                    "error": str(e),
                })

        return results

    def _success_response(self, req_id: int, result) -> dict:
        """构造成功响应"""
        return {
            "jsonrpc": "2.0",
            "result": result,
            "id": req_id,
        }

    def _error_response(self, req_id: int, code: int, message: str) -> dict:
        """构造错误响应"""
        return {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": req_id,
        }

    def run(self):
        """主循环：从 stdin 读取请求，通过 stdout 返回响应"""
        self._log("插件运行器已启动，等待请求...")

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                request = json.loads(line)
                response = self.handle_request(request)
                # 输出响应（单行 JSON + 换行）
                print(json.dumps(response, ensure_ascii=False), flush=True)
            except json.JSONDecodeError as e:
                self._log(f"JSON 解析失败: {e}")
                error_resp = self._error_response(0, -32700, f"JSON 解析错误: {e}")
                print(json.dumps(error_resp, ensure_ascii=False), flush=True)

        self._log("插件运行器已退出")


if __name__ == "__main__":
    runner = PluginRunner()
    runner.run()
