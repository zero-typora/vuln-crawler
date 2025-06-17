from dataclasses import dataclass
from typing import Optional

@dataclass
class VulnItem:
    name: str
    cve: Optional[str]
    date: str  # YYYY‑MM‑DD
    severity: str
    tags: Optional[str]
    source: str
    description: Optional[str]
    reference: Optional[str]

    def display_block(self) -> str:
        return (
            f"【漏洞名称】{self.name}\n"
            f"【CVE编号】{self.cve or ''}\n"
            f"【漏洞披露时间】{self.date}\n"
            f"【漏洞等级】{self.severity}\n"
            f"【漏洞标签】{self.tags or ''}\n"
            f"【漏洞来源】{self.source}\n"
            f"【漏洞描述】{self.description or ''}\n"
            f"【参考链接】{self.reference or ''}\n"
            f"【poc/exp】"
        )
