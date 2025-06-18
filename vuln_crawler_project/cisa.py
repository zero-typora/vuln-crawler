# cisa.py
"""
CISA Known Exploited Vulnerabilities (KEV) Catalog

- 按日期抓取：fetch_cisa(date) —— 保持原有逻辑
- 关键词 / CVE 搜索：search_cisa(keyword)
"""

from typing import List, Dict, Any
from models import VulnItem
from utils import _session

API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# -------------------------- 工具函数 --------------------------

def _get(v: Dict[str, Any], *names):
    """按多个备选键名依次取值，返回第一个非空"""
    for n in names:
        val = v.get(n)
        if val:
            return val
    return ""

# ------------------------ 按日期抓取 -------------------------

def fetch_cisa(date: str) -> List[VulnItem]:
    """
    返回 dateAdded == <date> 的全部条目（KEV 不区分严重度）
    date 参数格式: 'YYYY-MM-DD'
    """
    obj = _session.get(API, timeout=12).json()
    rows = obj.get("vulnerabilities", [])
    vulns: List[VulnItem] = []

    for r in rows:
        if _get(r, "dateAdded", "date_added") != date:
            continue
        vulns.append(
            VulnItem(
                name=_get(r, "vulnerabilityName", "vulnerability_name"),
                cve=_get(r, "cveID", "cve_id"),
                date=date,
                severity=None,
                tags=_get(r, "vendorProject", "vendor_project"),
                source="CISA KEV",
                description=_get(r, "shortDescription", "short_description"),
                reference=r.get("notes"),
            )
        )
    return vulns

# ------------------------- 关键词搜索 -------------------------

def search_cisa(keyword: str) -> List[VulnItem]:
    """
    关键词搜索：
      - 以 'CVE-' 开头 → 精确匹配 cveID
      - 其他 → 漏洞名称模糊包含（不区分大小写）

    返回满足条件的 VulnItem 列表，不做严重度过滤
    """
    obj = _session.get(API, timeout=12).json()
    rows = obj.get("vulnerabilities", [])
    vulns: List[VulnItem] = []

    kw_lower = keyword.lower()
    is_cve = kw_lower.startswith("cve-")

    for r in rows:
        name = _get(r, "vulnerabilityName", "vulnerability_name")
        cve  = _get(r, "cveID", "cve_id")

        # 过滤逻辑
        if is_cve:
            if cve.lower() != kw_lower:
                continue
        else:
            if kw_lower not in name.lower():
                continue

        vulns.append(
            VulnItem(
                name=name,
                cve=cve,
                date=_get(r, "dateAdded", "date_added"),
                severity=None,
                tags=_get(r, "vendorProject", "vendor_project"),
                source="CISA KEV",
                description=_get(r, "shortDescription", "short_description"),
                reference=r.get("notes"),
            )
        )

    return vulns
