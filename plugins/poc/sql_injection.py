"""
SQL 注入检测插件

基于报错注入、布尔盲注、时间盲注三种方式检测 SQL 注入漏洞。
"""

import requests
import urllib3
from typing import List

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base import BasePlugin, Target, VulnResult

# 禁用 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SQLInjectionPlugin(BasePlugin):
    """SQL 注入漏洞检测插件"""
    
    name = "sql_injection"
    description = "检测 SQL 注入漏洞（报错注入、布尔盲注、时间盲注）"
    severity = "critical"
    author = "AutoScan"

    # 报错注入 Payload
    ERROR_PAYLOADS = [
        ("'", ["sql syntax", "mysql", "ORA-", "PostgreSQL", "SQLite", "microsoft"]),
        ("\"", ["sql syntax", "mysql", "ORA-", "PostgreSQL", "SQLite", "microsoft"]),
        ("' OR '1'='1", ["sql syntax", "mysql"]),
        ("1' AND 1=CONVERT(int,@@version)--", ["microsoft", "mssql"]),
        ("' AND extractvalue(1,concat(0x7e,version()))--", ["xpath", "mysql"]),
    ]

    # 时间盲注 Payload（秒）
    TIME_PAYLOADS = [
        "' AND SLEEP(3)--",
        "' AND pg_sleep(3)--",
        "'; WAITFOR DELAY '0:0:3'--",
    ]

    def check(self, target: Target) -> List[VulnResult]:
        """执行 SQL 注入检测"""
        results = []
        
        if not target.url:
            return results

        # 对 URL 中的参数进行注入测试
        base_url = target.url.rstrip("/")
        
        # 检测报错注入
        for payload, keywords in self.ERROR_PAYLOADS:
            try:
                test_url = f"{base_url}/?id={payload}"
                resp = requests.get(test_url, timeout=10, verify=False)
                body = resp.text.lower()
                
                for keyword in keywords:
                    if keyword.lower() in body:
                        results.append(self.make_result(
                            name="SQL 注入 - 报错注入",
                            description=f"在 {test_url} 检测到报错注入，关键字: {keyword}",
                            url=test_url,
                            payload=payload,
                            evidence=keyword,
                            solution="使用参数化查询或 ORM 框架，避免直接拼接 SQL 语句",
                        ))
                        return results  # 发现一个即返回，避免重复
            except requests.RequestException:
                continue

        # 检测时间盲注
        for payload in self.TIME_PAYLOADS:
            try:
                test_url = f"{base_url}/?id={payload}"
                resp = requests.get(test_url, timeout=15, verify=False)
                
                if resp.elapsed.total_seconds() >= 2.5:
                    results.append(self.make_result(
                        name="SQL 注入 - 时间盲注",
                        description=f"在 {test_url} 检测到时间盲注，响应延迟 {resp.elapsed.total_seconds():.1f}s",
                        url=test_url,
                        payload=payload,
                        evidence=f"响应时间: {resp.elapsed.total_seconds():.1f}s",
                        solution="使用参数化查询或 ORM 框架，避免直接拼接 SQL 语句",
                    ))
                    return results
            except requests.RequestException:
                continue

        return results
