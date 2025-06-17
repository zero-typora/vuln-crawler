# oscs.py
"""
OSCS 开源安全情报列表
接口: https://www.oscs1024.com/oscs/v1/intelligence/list  (POST, JSON)
取指定日期且 level 为 高危 / 严重 的条目
"""
from typing import List
from models import VulnItem
from utils import _session

LIST_API = "https://www.oscs1024.com/oscs/v1/intelligence/list"
LEVEL_OK = {"高危", "严重"}          # 要“中危”也算就加进去


def fetch_oscs(date: str) -> List[VulnItem]:
    per_page, page = 100, 1
    vulns: List[VulnItem] = []

    while True:
        resp = _session.post(
            LIST_API,
            json={"page": page, "per_page": per_page},
            timeout=8,
        )
        resp.raise_for_status()
        rows = resp.json()["data"]["data"]
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
                    cve=None,                    # 列表页没有 CVE 字段
                    date=pub_date,
                    severity=row["level"],
                    tags=None,
                    source="OSCS",
                    description=None,
                    reference=row["url"],
                )
            )

        # 列表时间倒序；末条已早于目标日期就停止翻页
        if rows[-1]["public_time"].split("T")[0] < date:
            break
        page += 1

    return vulns
