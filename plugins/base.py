"""
AutoScan 漏洞检测插件基类

所有漏洞检测插件都必须继承 BasePlugin 并实现 check() 方法。
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict


@dataclass
class Target:
    """扫描目标信息"""
    host: str                           # 目标主机
    port: int = 0                       # 目标端口
    url: str = ""                       # 目标 URL
    service: Optional[Dict] = None      # 服务信息（名称、版本、Banner）
    extra: Dict[str, str] = field(default_factory=dict)


@dataclass
class VulnResult:
    """漏洞检测结果"""
    name: str                           # 漏洞名称
    description: str                    # 漏洞描述
    severity: str                       # 危害等级: critical, high, medium, low, info
    cve_id: str = ""                    # CVE 编号
    url: str = ""                       # 触发漏洞的 URL
    payload: str = ""                   # 使用的 Payload
    evidence: str = ""                  # 漏洞证据
    solution: str = ""                  # 修复建议
    plugin_name: str = ""               # 发现该漏洞的插件名称

    def to_dict(self) -> dict:
        """转换为字典"""
        return asdict(self)


class BasePlugin(ABC):
    """
    漏洞检测插件基类
    
    所有插件必须继承此类并实现 check() 方法。
    
    示例:
        class MyPlugin(BasePlugin):
            name = "my_plugin"
            description = "自定义漏洞检测"
            severity = "medium"
            
            def check(self, target: Target) -> List[VulnResult]:
                # 执行检测逻辑
                return []
    """
    
    name: str = "base_plugin"           # 插件名称（唯一标识）
    description: str = ""               # 插件描述
    severity: str = "info"              # 默认危害等级
    author: str = ""                    # 作者
    enabled: bool = True                # 是否启用

    @abstractmethod
    def check(self, target: Target) -> List[VulnResult]:
        """
        执行漏洞检测
        
        参数:
            target: 扫描目标信息
            
        返回:
            漏洞检测结果列表（空列表表示未发现漏洞）
        """
        raise NotImplementedError

    def make_result(self, name: str, description: str, **kwargs) -> VulnResult:
        """
        便捷方法：创建漏洞结果对象
        
        自动填充 severity 和 plugin_name 字段。
        """
        return VulnResult(
            name=name,
            description=description,
            severity=kwargs.get("severity", self.severity),
            cve_id=kwargs.get("cve_id", ""),
            url=kwargs.get("url", ""),
            payload=kwargs.get("payload", ""),
            evidence=kwargs.get("evidence", ""),
            solution=kwargs.get("solution", ""),
            plugin_name=self.name,
        )

    def info(self) -> dict:
        """返回插件信息"""
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
        }
