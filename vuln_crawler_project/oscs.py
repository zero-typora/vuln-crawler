# oscs.py
"""
OSCS 开源安全情报

接口:
    https://www.oscs1024.com/oscs/v1/intelligence/list   (POST, JSON)

功能:
    - fetch_oscs(date)     —— 仍按日期抓取 (高危/严重)
    - search_oscs(keyword) —— 新增关键词 / CVE 搜索
"""

from typing import List
import random, time
from models import VulnItem
from utils import _session

LIST_API = "https://www.oscs1024.com/oscs/v1/intelligence/list"
LEVEL_OK = {"严重", "高危"}        # 要“中危”也算就加进去

# ------------------------- 内部通用函数 -------------------------

def _post_page(page: int, per_page: int = 100, keyword: str = "") -> dict:
    """
    POST 请求分页列表；服务器 5xx 时重试 ≤ 3 次
    返回形如 {"data":{"data":[…]}} 的最外层 dict
    """
    payload = {"page": page, "per_page": per_page}
    if keyword:
        payload["keyword"] = keyword

    for attempt in range(3):
        try:
            r = _session.post(LIST_API, json=payload, timeout=8)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            print(f"[OSCS] page {page} attempt {attempt+1}: {e}")
            time.sleep(random.uniform(1, 2))
    return {}

# --------------------------- 搜索 ---------------------------

def search_oscs(keyword: str) -> List[VulnItem]:
    """
    关键词搜索:
        - 以 'CVE-' 开头 (忽略大小写) → 精确匹配 cve_id
        - 否则对 title 做包含匹配 (不区分大小写)
    仅保留 level ∈ LEVEL_OK
    """
    vulns: List[VulnItem] = []
    page, per_page = 1, 100
    is_cve = keyword.lower().startswith("cve-")

    while True:
        j = _post_page(page, per_page, keyword)
        rows = j.get("data", {}).get("data", [])
        if not rows:
            break

        for row in rows:
            if row["level"] not in LEVEL_OK:
                continue

            if is_cve:
                if keyword.lower() != (row.get("cve_id") or "").lower():
                    continue
            else:
                if keyword.lower() not in row["title"].lower():
                    continue

            vulns.append(
                VulnItem(
                    name=row["title"],
                    cve=row.get("cve_id"),
                    date=row["public_time"].split("T")[0],
                    severity=row["level"],
                    tags=None,
                    source="OSCS",
                    description=row.get("desc") or row.get("description"),
                    reference=row.get("url"),
                )
            )

        page += 1

    return vulns

# --------------------------- 按日期抓取 ---------------------------

def fetch_oscs(date: str) -> List[VulnItem]:
    """
    返回发布日期 == <date> 且 level ∈ LEVEL_OK 的列表
    """
    vulns: List[VulnItem] = []
    page, per_page = 1, 100

    while True:
        j = _post_page(page, per_page)
        rows = j.get("data", {}).get("data", [])
        if not rows:
            break

        for row in rows:
            pub_date = row["public_time"].split("T")[0]
            if pub_date != date:
                continue
            if row["level"] not in LEVEL_OK:
                continue

            vulns.append(
                VulnItem(
                    name=row["title"],
                    cve=row.get("cve_id"),   # 列表有时带 cve_id；若无留空
                    date=pub_date,
                    severity=row["level"],
                    tags=None,
                    source="OSCS",
                    description=row.get("desc") or row.get("description"),
                    reference=row.get("url"),
                )
            )

        # 列表按时间倒序；如果最后一条已早于目标日期就不用翻下去了
        last_date = rows[-1]["public_time"].split("T")[0]
        if last_date < date:
            break

        page += 1

    return vulns
