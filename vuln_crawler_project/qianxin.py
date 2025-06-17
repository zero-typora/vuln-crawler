# qianxin.py
"""
360 CERT one-day 高危 / 严重 漏洞列表
接口: https://ti.qianxin.com/alpha-api/v2/vuln/one-day?date=YYYY-MM-DD
"""
from typing import List
from models import VulnItem
from utils import _session

API = "https://ti.qianxin.com/alpha-api/v2/vuln/one-day"

# 需要“中危”也统计就在这里加
LEVEL_OK = {"高危", "极危", "严重"}


def _collect_rows(obj) -> List[dict]:
    """
    新版返回:
    {
        "status": 10000,
        "data": {
            "vuln_add": [...],
            "vuln_update": [...],
            "key_vuln_add": [...],
            "poc_exp_add": [...],
            "patch_add": [...],
            ...
        }
    }
    把五类列表全部拼一块儿返回。
    """
    rows = []
    data = obj.get("data", {})
    for key in ("vuln_add", "vuln_update", "key_vuln_add", "poc_exp_add", "patch_add"):
        val = data.get(key)
        if isinstance(val, list):
            rows.extend(val)
    return rows


def _pick_level(row: dict) -> str:
    """
    各种可能的严重度字段兜底处理
    """
    for k in ("rating_level", "level", "risk_level", "rating_level_cn"):
        if row.get(k):
            return row[k]
    return "未知"


def fetch_qianxin(date: str) -> List[VulnItem]:
    resp = _session.get(API, params={"date": date}, timeout=8)
    resp.raise_for_status()

    rows = _collect_rows(resp.json())
    vulns: List[VulnItem] = []

    for row in rows:
        # 日期字段固定叫 publish_time，格式 YYYY-MM-DD
        pub_date = row.get("publish_time") or row.get("date") or ""
        if pub_date != date:
            continue

        level = _pick_level(row)
        if level not in LEVEL_OK:
            continue

        vulns.append(VulnItem(
            name=row.get("vuln_name") or row.get("title") or "未知漏洞",
            cve=row.get("cve_code") or row.get("cve_id"),
            date=pub_date,
            severity=level,
            tags=row.get("vuln_type") or row.get("threat_category"),
            source="奇安信 CERT",
            description=row.get("description"),
            reference=None,
        ))

    return vulns
