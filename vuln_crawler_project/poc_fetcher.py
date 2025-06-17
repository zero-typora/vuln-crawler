"""
GitHub PoC / EXP 聚合器
-----------------------
search_github  —— 关键词列表 → GitHub Repos 搜索结果 URL
fetch_poc_urls —— (cve, 漏洞名, 其它编号) → 去重 URL 列表
set_github_token —— 供 GUI 动态注入 / 清空 PAT
"""

from __future__ import annotations
import json, re, time, threading, requests
from pathlib import Path
from typing import List

# ---------- 基本常量 ----------
GITHUB_API = "https://api.github.com/search/repositories"
HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "vuln-crawler/1.2",
}
CACHE_DIR  = Path.home() / ".vuln_crawler_cache"
CACHE_FILE = CACHE_DIR / "github_poc_cache.json"
CACHE_TTL  = 24 * 3600          # 24 h
_LOCK = threading.Lock()

# ---------- Token 注入 ----------
def set_github_token(token: str | None):
    if token:
        HEADERS["Authorization"] = f"Bearer {token.strip()}"
    else:
        HEADERS.pop("Authorization", None)

# ---------- 缓存 ----------
def _load_cache() -> dict:
    if CACHE_FILE.exists() and time.time() - CACHE_FILE.stat().st_mtime < CACHE_TTL:
        try:
            return json.loads(CACHE_FILE.read_text())
        except Exception:
            pass
    return {}

def _save_cache(d: dict):
    CACHE_DIR.mkdir(exist_ok=True)
    CACHE_FILE.write_text(json.dumps(d))

# ---------- 单次仓库查询 ----------
def _query_repos(q: str, max_hits: int) -> list[str]:
    params = {"q": q, "per_page": max_hits, "sort": "updated"}
    try:
        r = requests.get(GITHUB_API, headers=HEADERS, params=params, timeout=10)
        r.raise_for_status()
        return [it["html_url"] for it in r.json().get("items", [])]
    except Exception as e:
        print("[PoC] github search error:", e)
        return []

# ---------- 主搜索 ----------
def search_github(keywords: List[str], max_hits: int = 2) -> List[str]:
    if not keywords:
        return []

    cache_key = "|".join(keywords) + f"|{max_hits}"
    with _LOCK:
        cache = _load_cache()
        if cache_key in cache:
            return cache[cache_key]

    hits: list[str] = []

    # ① 精确 —— 只用第一个关键词（通常是 CVE）限制在 name/description
    exact_q = f'"{keywords[0]}" in:name,description'
    hits += _query_repos(exact_q, max_hits)

    # ② 兜底 —— 其余关键词 OR 补齐
    if len(hits) < max_hits and len(keywords) > 1:
        or_q = " OR ".join(f'"{kw}"' for kw in keywords)
        for u in _query_repos(or_q, max_hits * 2):
            if u not in hits:
                hits.append(u)
            if len(hits) >= max_hits:
                break

    hits = hits[:max_hits]

    with _LOCK:
        cache[cache_key] = hits
        _save_cache(cache)
    return hits

# ---------- 名称分词 ----------
def _extract_name_keywords(name: str) -> List[str]:
    noise = {"漏洞", "远程", "代码", "执行", "权限", "提升", "信息", "泄露"}
    parts = re.split(r"[()/、\-_\s]", name)
    return [p for p in parts if p and p.lower() not in noise][:5]

# ---------- 对外 ----------
def fetch_poc_urls(cve: str | None,
                   vuln_name: str | None,
                   vuln_id: str | None) -> List[str]:

    kws: list[str] = []
    if cve:
        kws.append(cve)                 # 保证 CVE 在第一位
    if vuln_id and vuln_id not in kws:
        kws.append(vuln_id)
    if vuln_name:
        kws += _extract_name_keywords(vuln_name)

    return search_github(kws, max_hits=2)
