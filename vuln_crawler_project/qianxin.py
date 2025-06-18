# qianxin.py
"""
奇安信 CERT — 每日与关键词漏洞接口

接口一览
========
1. 按日期抓取（旧逻辑，保留）
   GET https://ti.qianxin.com/alpha-api/v2/vuln/one-day?date=YYYY-MM-DD

2. 关键词 / CVE 搜索（新增）
   GET https://ti.qianxin.com/alpha-api/v2/vuln/search
       params: keyword=<str>, page=<int>, page_size=<int>

字段说明（两端点返回行结构相近）
------------
- publish_time / date         发布时间 (YYYY-MM-DD)
- vuln_name / title           漏洞标题
- cve_code / cve_id           CVE
- rating_level / level        严重度 (高危 / 极危 / 严重 / 中危 / 低危)
"""

from typing import List, Dict, Any
import time, random
from models import VulnItem
from utils import _session

API_ONE_DAY   = "https://ti.qianxin.com/alpha-api/v2/vuln/one-day"
API_SEARCH    = "https://ti.qianxin.com/alpha-api/v2/vuln/search"

# 要“中危”也算就在这里加
LEVEL_OK = {"高危", "极危", "严重"}

# -------------------------------------------------------------------
# 公共小工具
# -------------------------------------------------------------------

def _collect_rows(obj: Dict[str, Any]) -> List[dict]:
    """把 one-day 返回的五个列表合并"""
    rows = []
    data = obj.get("data", {})
    for key in ("vuln_add", "vuln_update", "key_vuln_add",
                "poc_exp_add", "patch_add"):
        val = data.get(key)
        if isinstance(val, list):
            rows.extend(val)
    return rows

def _pick_level(row: dict) -> str:
    """不同接口的严重度字段兜底"""
    for k in ("rating_level", "level", "risk_level", "rating_level_cn"):
        if row.get(k):
            return row[k]
    return "未知"

# -------------------------------------------------------------------
# 1) 关键词 / CVE 搜索  ------------------------------------------------
# -------------------------------------------------------------------

def _search_page(keyword: str, page: int, page_size: int = 100) -> Dict[str, Any]:
    """封装搜索分页请求（含重试）"""
    params = {"keyword": keyword, "page": page, "page_size": page_size}
    for attempt in range(3):
        try:
            r = _session.get(API_SEARCH, params=params, timeout=8)
            r.raise_for_status()
            return r.json().get("data", {})   # 返回 {"rows":[...], "hasNext":bool}
        except Exception as e:
            print(f"[Qianxin search] page {page} attempt {attempt+1}: {e}")
            time.sleep(random.uniform(1, 2))
    return {}

def search_qianxin(keyword: str) -> List[VulnItem]:
    """
    关键词搜索：
      - 以 'CVE-' 开头 → 精确匹配 CVE
      - 否则 → 标题模糊 (不区分大小写)
    结果仅保留 LEVEL_OK
    """
    vulns: List[VulnItem] = []
    page, page_size = 1, 100
    kw_lower = keyword.lower()
    is_cve = kw_lower.startswith("cve-")

    while True:
        data = _search_page(keyword, page, page_size)
        rows = data.get("rows") or data.get("data") or []
        if not rows:
            break

        for row in rows:
            level = _pick_level(row)
            if level not in LEVEL_OK:
                continue

            title = row.get("vuln_name") or row.get("title") or ""
            cve   = row.get("cve_code") or row.get("cve_id") or ""

            # 过滤逻辑
            if is_cve:
                if cve.lower() != kw_lower:
                    continue
            else:
                if kw_lower not in title.lower():
                    continue

            vulns.append(
                VulnItem(
                    name=title or "未知漏洞",
                    cve=cve,
                    date=row.get("publish_time") or row.get("date") or "",
                    severity=level,
                    tags=row.get("vuln_type") or row.get("threat_category"),
                    source="奇安信 CERT",
                    description=row.get("description"),
                    reference=None,
                )
            )

        # 翻页控制
        if not data.get("hasNext") and len(rows) < page_size:
            break
        page += 1

    return vulns

# -------------------------------------------------------------------
# 2) 按日期抓取 (保持原状) --------------------------------------------
# -------------------------------------------------------------------

def fetch_qianxin(date: str) -> List[VulnItem]:
    """拉取指定日期的高危 / 极危 / 严重漏洞（旧接口）"""
    resp = _session.get(API_ONE_DAY, params={"date": date}, timeout=8)
    resp.raise_for_status()

    rows = _collect_rows(resp.json())
    vulns: List[VulnItem] = []

    for row in rows:
        pub_date = row.get("publish_time") or row.get("date") or ""
        if pub_date != date:
            continue

        level = _pick_level(row)
        if level not in LEVEL_OK:
            continue

        vulns.append(
            VulnItem(
                name=row.get("vuln_name") or row.get("title") or "未知漏洞",
                cve=row.get("cve_code") or row.get("cve_id"),
                date=pub_date,
                severity=level,
                tags=row.get("vuln_type") or row.get("threat_category"),
                source="奇安信 CERT",
                description=row.get("description"),
                reference=None,
            )
        )

    return vulns
