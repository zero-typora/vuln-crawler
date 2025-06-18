# changtin.py  ⬅️ 完全替换下面同名部分即可
from typing import List
import datetime as dt, time, random
from models import VulnItem
from utils import _session

API = "https://rivers.chaitin.cn/api/vuln/list"

SEV_MAP = {
    "critical":  "严重",
    "high":      "高危",
    "urgent":    "高危",
    "important": "中危",
}
LEVEL_OK = set(SEV_MAP.keys())

# ---------- 共用内部函数 ----------
def _get_page(page: int, size: int = 100, keyword: str = ""):
    """携带 keyword 取分页数据；服务器 5xx 时重试 3 次"""
    for attempt in range(3):
        try:
            params = {"page": page, "size": size}
            if keyword:                       # 仅搜索时才带
                params["keyword"] = keyword
            r = _session.get(API, params=params, timeout=8)
            r.raise_for_status()              # 4xx/5xx 抛异常 → 触发重试
            return r.json()["data"]           # Rivers: {"code":0,"data":{...}}
        except Exception as e:
            print(f"[Rivers] page {page} attempt {attempt+1}: {e}")
            time.sleep(random.uniform(1, 2))
    return None

# ---------- 搜索 ----------
def search_changtin(keyword: str) -> List[VulnItem]:
    vulns, page, size = [], 1, 100
    is_cve = keyword.lower().startswith("cve-")

    while True:
        data = _get_page(page, size, keyword)
        if not data or not data.get("list"):
            break

        for row in data["list"]:
            sev = row["severity"]
            if sev not in LEVEL_OK:
                continue
            if (is_cve and (row.get("cve_id") or "").lower() != keyword.lower()) \
               or (not is_cve and keyword.lower() not in row["title"].lower()):
                continue

            vulns.append(
                VulnItem(
                    name=row["title"],
                    cve=row.get("cve_id"),
                    date=row["disclosure_date"].split(" ")[0],
                    severity=SEV_MAP.get(sev, sev),
                    tags=row.get("weakness"),
                    source="长亭 Rivers",
                    description=row.get("summary"),
                    reference=row.get("references") or "",
                )
            )

        if page >= data["total_page"]:
            break
        page += 1
    return vulns

# ---------- 日期抓取（原逻辑完全保留） ----------
def fetch_changtin(date: str) -> List[VulnItem]:
    vulns, target = [], dt.date.fromisoformat(date)
    page, size = 1, 100
    while True:
        data = _get_page(page, size)
        if not data or not data.get("list"):
            break
        for row in data["list"]:
            if row["severity"] not in LEVEL_OK:
                continue
            disc = row["disclosure_date"].split(" ")[0]
            if disc != date:
                continue
            vulns.append(
                VulnItem(
                    name=row["title"],
                    cve=row.get("cve_id"),
                    date=disc,
                    severity=SEV_MAP.get(row["severity"], row["severity"]),
                    tags=row.get("weakness"),
                    source="长亭 Rivers",
                    description=row.get("summary"),
                    reference=row.get("references") or "",
                )
            )
        last_date = data["list"][-1]["disclosure_date"].split(" ")[0]
        if dt.date.fromisoformat(last_date) < target or page >= data["total_page"]:
            break
        page += 1
    return vulns
