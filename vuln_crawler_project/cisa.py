# cisa.py
from typing import List, Dict, Any
from models import VulnItem
from utils import _session

API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def _get(v: Dict[str, Any], *names):
    for n in names:
        if n in v and v[n]:
            return v[n]

def fetch_cisa(date: str) -> List[VulnItem]:
    """返回 dateAdded == date 的所有条目（不区分严重度）"""
    obj = _session.get(API, timeout=12).json()
    rows = obj.get("vulnerabilities", [])
    vulns: List[VulnItem] = []

    for r in rows:
        if _get(r, "dateAdded", "date_added") != date:
            continue
        vulns.append(VulnItem(
            name=_get(r, "vulnerabilityName", "vulnerability_name"),
            cve=_get(r, "cveID", "cve_id"),
            date=date,
            severity=None,                       # KEV 未提供严重度
            tags=_get(r, "vendorProject", "vendor_project"),
            source="CISA KEV",
            description=_get(r, "shortDescription", "short_description"),
            reference=r.get("notes"),
        ))
    return vulns
