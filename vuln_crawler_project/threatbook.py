# threatbook.py
"""
ThreatBook 漏洞首页

接口
----
https://x.threatbook.com/v5/node/vul_module/homePage  (GET, JSON)

功能
----
- fetch_threatbook(date)   —— 按日期过滤 premium + highRisk 列表
- search_threatbook(keyword) —— 关键词 / CVE 搜索
"""

from typing import List, Optional
import random, time
from models import VulnItem
from utils import _session

API = "https://x.threatbook.com/v5/node/vul_module/homePage"

_headers = {
    "Referer": "https://x.threatbook.com/",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "User-Agent": "Mozilla/5.0",
    # 如需访问登录后条目，可在 GUI 中通过 set_cookie() 注入
    # "Cookie": "TBOOK_SESSIONID=xxxxxxxxxxxxxxxx;",
}

# ------------------- GUI 用 Cookie 动态注入 -------------------

def set_cookie(raw: str) -> None:
    """
    在 GUI 中粘贴完整 Cookie 后调用；传空串则清空
    """
    raw = raw.strip()
    if raw:
        _headers["Cookie"] = raw
    else:
        _headers.pop("Cookie", None)

# --------------------- 辅助解析为 VulnItem ---------------------

def _to_item(it: dict) -> Optional[VulnItem]:
    ts = it.get("vuln_update_time") or it.get("vulnPublishTime")
    if not ts:
        return None
    return VulnItem(
        name=it.get("vuln_name_zh") or it.get("vulnNameZh") or it.get("title", "未知漏洞"),
        cve=it.get("id"),
        date=ts[:10],                       # 仅取 'YYYY-MM-DD'
        severity=it.get("riskLevel") or "高风险",
        tags=None,
        source="ThreatBook",
        description=None,
        reference=None,
    )

def _fetch_homepage(retry: int = 3) -> dict:
    """
    GET homePage 接口，带简单退避重试；成功返回 .json()['data']
    """
    for attempt in range(retry):
        try:
            r = _session.get(API, headers=_headers, timeout=8)
            r.raise_for_status()
            return r.json().get("data", {})
        except Exception as e:
            print(f"[ThreatBook] attempt {attempt+1}: {e}")
            time.sleep(random.uniform(1, 2))
    return {}

# ------------------------ 按日期抓取 ------------------------

def fetch_threatbook(date: str) -> List[VulnItem]:
    """
    返回 vuln_update_time 以 <date> 开头的 premium + highRisk 条目
    """
    data = _fetch_homepage()
    vulns: List[VulnItem] = []

    for key in ("premium", "highRisk"):
        for it in data.get(key, []):
            item = _to_item(it)
            if item and item.date == date:
                vulns.append(item)

    return vulns

# --------------------- 关键词 / CVE 搜索 ---------------------

def search_threatbook(keyword: str) -> List[VulnItem]:
    """
    关键词搜索：
      - 以 'CVE-' 开头 → 精确匹配 id 字段
      - 否则 → 名称模糊匹配（大小写不敏感）
    搜索范围仅限 homePage 中的 premium + highRisk
    """
    data = _fetch_homepage()
    vulns: List[VulnItem] = []

    kw_lower = keyword.lower()
    is_cve = kw_lower.startswith("cve-")

    for key in ("premium", "highRisk"):
        for it in data.get(key, []):
            item = _to_item(it)
            if not item:
                continue

            if is_cve:
                if (item.cve or "").lower() != kw_lower:
                    continue
            else:
                if kw_lower not in item.name.lower():
                    continue

            vulns.append(item)

    return vulns
