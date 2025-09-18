"""
XSS（跨站脚本攻击）检测插件

检测反射型 XSS 漏洞，通过注入测试 Payload 并检查响应中是否包含未转义的内容。
"""

import requests
import urllib.parse
import urllib3
from typing import List

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base import BasePlugin, Target, VulnResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class XSSDetectorPlugin(BasePlugin):
    """XSS 漏洞检测插件"""

    name = "xss_detector"
    description = "检测反射型 XSS（跨站脚本攻击）漏洞"
    severity = "high"
    author = "AutoScan"

    # XSS 测试 Payload 及对应的检测标记
    PAYLOADS = [
        ('<script>alert("XSS")</script>', '<script>alert("XSS")</script>'),
        ('<img src=x onerror=alert(1)>', '<img src=x onerror=alert(1)>'),
        ('"><svg/onload=alert(1)>', '"><svg/onload=alert(1)>'),
        ("'><img src=x onerror=alert(1)>", "'><img src=x onerror=alert(1)>"),
        ('<body onload=alert(1)>', '<body onload=alert(1)>'),
        ('javascript:alert(1)', 'javascript:alert(1)'),
        ('"><iframe src="javascript:alert(1)">', 'iframe src="javascript:alert(1)">'),
    ]

    def check(self, target: Target) -> List[VulnResult]:
        """执行 XSS 检测"""
        results = []

        if not target.url:
            return results

        base_url = target.url.rstrip("/")

        for payload, marker in self.PAYLOADS:
            try:
                # GET 参数注入测试
                encoded_payload = urllib.parse.quote(payload, safe='')
                test_url = f"{base_url}/?q={encoded_payload}"
                
                resp = requests.get(test_url, timeout=10, verify=False)
                
                # 检查响应中是否包含未转义的 Payload
                if marker in resp.text:
                    results.append(self.make_result(
                        name="反射型 XSS",
                        description=f"在 {base_url} 检测到反射型 XSS，Payload 未被过滤或转义",
                        url=test_url,
                        payload=payload,
                        evidence=f"响应中包含未转义的内容: {marker[:50]}",
                        solution="对用户输入进行 HTML 实体编码，使用 Content-Security-Policy 响应头",
                    ))
                    return results  # 发现一个即返回
            except requests.RequestException:
                continue

        return results
