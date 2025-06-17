"""
公共工具：HTTP session、日期、去重合并
"""
import datetime as _dt
from typing import Dict, List, Callable, Optional
import requests
from models import VulnItem

# ---------------- HTTP 会话 ----------------
_session = requests.Session()
_session.headers.update({
    "User-Agent": "Mozilla/5.0 vuln-crawler/1.1 (+https://example.com)",
    "Accept": "application/json, text/plain, */*",
    "Connection": "close",
})

# ---------------- 去重合并 ----------------
Fetcher = Callable[[str], List[VulnItem]]

def fetch_all(target_date: str, fetchers: List[Fetcher]) -> List[VulnItem]:
    seen: Dict[str, VulnItem] = {}
    for fn in fetchers:
        try:
            items = fn(target_date)
            print(f"[{fn.__name__}] {len(items)} item(s)")
        except Exception as e:
            print(f"[{fn.__name__}] ERROR → {e}")
            continue

        for it in items:
            key = it.cve or f"{it.name}_{it.date}"
            seen.setdefault(key, it)

    return list(seen.values())

# ---------------- 代理设置 ----------------
def _normalize(url: Optional[str], default_scheme: str) -> Optional[str]:
    """
    若 url 为 '127.0.0.1:7890' → 自动补 'http://127.0.0.1:7890'
    若已带 scheme（http://、https://、socks5://…）则原样返回
    """
    if not url:
        return None
    url = url.strip()
    if "://" not in url:
        url = f"{default_scheme}://{url}"
    return url

def set_proxy(http_url: Optional[str] = None,
              https_url: Optional[str] = None) -> None:
    """
    运行时更新代理:
      http_url  —— 形如 '127.0.0.1:7890' 或完整 'http://...' / 'socks5://...'
      https_url —— 同上
    传 None / '' 表示清空对应协议代理
    """
    http_url  = _normalize(http_url,  "http")
    https_url = _normalize(https_url, "http")   # HTTPS 代理常用 http CONNECT 隧道

    proxies = _session.proxies.copy()
    if http_url:
        proxies['http'] = http_url
    else:
        proxies.pop('http', None)

    if https_url:
        proxies['https'] = https_url
    else:
        proxies.pop('https', None)

    _session.proxies = proxies

# ---------------- 小工具 ----------------
def today() -> str:
    return _dt.date.today().isoformat()
