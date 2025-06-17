# threatbook.py
"""
ThreatBook 漏洞首页
接口: https://x.threatbook.com/v5/node/vul_module/homePage
抓取 premium + highRisk，按 vuln_update_time 过滤日期
"""
from typing import List, Optional
from models import VulnItem
from utils import _session

API = "https://x.threatbook.com/v5/node/vul_module/homePage"

_headers = {
    "Referer": "https://x.threatbook.com/",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "User-Agent": "Mozilla/5.0",
    # 如需登录条目，把浏览器里 TBOOK_SESSIONID=... 粘到这里，
    # 或在 GUI 中通过 set_cookie() 动态注入
    # "Cookie": "TBOOK_SESSIONID=xxxxxxxxxxxxxxxx;",
}

# ---------- 供 GUI 调用 ----------
def set_cookie(raw: str) -> None:
    """
    在 GUI 中粘贴完整 Cookie 后调用，或传空串来清空
    """
    raw = raw.strip()
    if raw:
        _headers["Cookie"] = raw
    else:
        _headers.pop("Cookie", None)


# ---------- 辅助解析 ----------
def _to_item(it: dict) -> Optional[VulnItem]:
    ts = it.get("vuln_update_time") or it.get("vulnPublishTime")
    if not ts:
        return None

    return VulnItem(
        name=it.get("vuln_name_zh") or it.get("vulnNameZh") or it.get("title", "未知漏洞"),
        cve=it.get("id"),
        date=ts,
        severity=it.get("riskLevel") or "高风险",
        tags=None,
        source="ThreatBook",
        description=None,
        reference=None,
    )


# ---------- 主入口 ----------
def fetch_threatbook(date: str) -> List[VulnItem]:
    r = _session.get(API, headers=_headers, timeout=8)
    r.raise_for_status()
    data = r.json().get("data", {})

    vulns: List[VulnItem] = []
    for key in ("premium", "highRisk"):
        arr = data.get(key)
        if isinstance(arr, list):
            for it in arr:
                item = _to_item(it)
                if item and item.date.startswith(date):
                    vulns.append(item)

    return vulns
