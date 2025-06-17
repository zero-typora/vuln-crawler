# changtin.py
"""
长亭 Rivers 漏洞 Feed
接口: https://rivers.chaitin.cn/api/vuln/list
"""

from typing import List
import datetime as dt, time, random
from models import VulnItem
from utils import _session

API = "https://rivers.chaitin.cn/api/vuln/list"

# 风险级别映射
SEV_MAP = {
    "critical":  "严重",
    "high":      "高危",
    "urgent":    "高危",
    "important": "中危",
}
LEVEL_OK = set(SEV_MAP.keys())          # 需要“中危”以上

# ---------------------------- 核心 ----------------------------

def _get_page(page: int, size: int = 100):
    """退避重试拿页面 JSON；若 5xx 最多尝试 3 次"""
    for attempt in range(3):
        try:
            r = _session.get(API,
                             params={"page": page, "size": size, "keyword": ""},
                             timeout=8)
            if r.status_code >= 500:
                raise RuntimeError(f"Rivers 5xx")
            return r.json()["data"]
        except Exception as e:
            print(f"[Rivers] page {page} attempt {attempt+1} → {e}")
            time.sleep(random.uniform(1, 2))
    return None     # 连续失败直接放弃


def fetch_changtin(date: str) -> List[VulnItem]:
    """抓取指定日期的高危 / 严重漏洞（含 urgent / important）"""
    vulns: List[VulnItem] = []
    target = dt.date.fromisoformat(date)

    page, size = 1, 100
    while True:
        data = _get_page(page, size)
        if not data:
            break

        for row in data["Data"]:
            sev = row["severity"]
            if sev not in LEVEL_OK:
                continue

            disc = row["disclosure_date"].split(" ")[0]     # 'YYYY-MM-DD ...'
            if disc != date:
                continue

            vulns.append(
                VulnItem(
                    name=row["title"],
                    cve=row.get("cve_id"),
                    date=disc,
                    severity=SEV_MAP.get(sev, sev),
                    tags=row.get("weakness"),
                    source="长亭 Rivers",
                    description=row.get("summary"),
                    reference=row.get("references") or "",
                )
            )

        # 翻页：若已到末页或下一页最早日期早于目标，就停止
        if page >= data["total_page"]:
            break
        last_date = data["Data"][-1]["disclosure_date"].split(" ")[0]
        if dt.date.fromisoformat(last_date) < target:
            break
        page += 1

    return vulns
