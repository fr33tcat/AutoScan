"""
敏感文件探测插件

检测 Web 服务器上常见的敏感文件和目录泄露。
"""

import requests
import urllib3
from typing import List

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base import BasePlugin, Target, VulnResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SensitiveFilesPlugin(BasePlugin):
    """敏感文件探测插件"""

    name = "sensitive_files"
    description = "探测 Web 服务器上的敏感文件和目录泄露"
    severity = "medium"
    author = "AutoScan"

    # 敏感路径列表：(路径, 描述, 危害等级, 检测关键字)
    SENSITIVE_PATHS = [
        # 版本控制泄露
        ("/.git/config", "Git 仓库配置泄露", "high", ["[core]", "[remote", "repositoryformatversion"]),
        ("/.svn/entries", "SVN 仓库泄露", "high", ["dir", "svn"]),
        ("/.hg/store/", "Mercurial 仓库泄露", "high", []),

        # 环境配置泄露
        ("/.env", "环境变量文件泄露", "critical", ["DB_", "APP_KEY", "SECRET", "PASSWORD", "API_KEY"]),
        ("/config.php.bak", "PHP 配置备份文件", "high", ["<?php", "config"]),
        ("/wp-config.php.bak", "WordPress 配置备份", "critical", ["DB_NAME", "DB_USER"]),

        # 备份文件
        ("/backup.zip", "备份压缩包", "high", []),
        ("/backup.tar.gz", "备份压缩包", "high", []),
        ("/db.sql", "数据库备份", "critical", []),
        ("/database.sql", "数据库备份", "critical", []),

        # 服务器信息泄露
        ("/robots.txt", "Robots.txt 文件", "info", ["Disallow", "Allow", "User-agent"]),
        ("/.DS_Store", "macOS 目录文件泄露", "low", []),
        ("/phpinfo.php", "PHP 信息泄露", "medium", ["phpinfo", "PHP Version"]),
        ("/server-status", "Apache 状态页面", "medium", ["Apache Server Status"]),
        ("/nginx.conf", "Nginx 配置泄露", "high", ["server", "location"]),

        # 常见后台路径
        ("/admin/", "后台管理入口", "info", []),
        ("/manager/", "管理界面", "info", []),
        ("/phpmyadmin/", "phpMyAdmin", "medium", ["phpMyAdmin"]),

        # API 文档泄露
        ("/swagger-ui.html", "Swagger API 文档", "low", ["swagger"]),
        ("/api-docs", "API 文档", "low", []),
        ("/v2/api-docs", "Swagger v2 API 文档", "low", []),
    ]

    def check(self, target: Target) -> List[VulnResult]:
        """执行敏感文件探测"""
        results = []

        if not target.url:
            return results

        base_url = target.url.rstrip("/")

        for path, desc, severity, keywords in self.SENSITIVE_PATHS:
            try:
                test_url = f"{base_url}{path}"
                resp = requests.get(
                    test_url,
                    timeout=5,
                    verify=False,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )

                # 跳过 404 和重定向
                if resp.status_code in [404, 403, 301, 302]:
                    continue

                # 如果有关键字，验证响应内容
                if keywords:
                    body = resp.text
                    if not any(kw in body for kw in keywords):
                        continue

                # 跳过过小的空页面（可能是默认页面）
                if resp.status_code == 200 and len(resp.text) < 10 and not keywords:
                    continue

                results.append(self.make_result(
                    name=f"敏感文件泄露 - {desc}",
                    description=f"发现敏感路径: {test_url}（状态码: {resp.status_code}）",
                    severity=severity,
                    url=test_url,
                    evidence=f"HTTP {resp.status_code}, 响应长度: {len(resp.text)} 字节",
                    solution="删除或限制访问敏感文件，配置 Web 服务器禁止访问隐藏文件",
                ))

            except requests.RequestException:
                continue

        return results
