# vuln_search.py
"""
统一关键词 / CVE 搜索入口
---------------------------------
依赖各数据源的 search_xxx(keyword) 函数，而不是 fetch_xxx(date)。
这样就不会再把空日期传给日期接口，避免 isoformat 解析报错。
"""

import threading
from typing import List, Optional
from models import VulnItem
import changtin, oscs, qianxin, threatbook, cisa

# 仅放“搜索入口” ↓↓↓
SEARCHERS = {
    "长亭":       changtin.search_changtin,
    "OSCS":      oscs.search_oscs,
    "奇安信":     qianxin.search_qianxin,
    "ThreatBook": threatbook.search_threatbook,
    "CISA":      cisa.search_cisa,
}

def search_vulns(
    keyword: str,
    sources: Optional[List[str]] = None,
    max_workers: int = 5,
) -> List[VulnItem]:
    """
    根据 CVE 或漏洞名称搜索漏洞（不限制日期）
    ------------------------------------------------
    * CVE：忽略大小写 **精确匹配**（keyword 以 'CVE-' 开头）
    * 名称：忽略大小写 **模糊包含**
    * 若 sources 为 None → 查询 SEARCHERS 全部源
    """
    if sources is None:
        sources = SEARCHERS.keys()

    results: List[VulnItem] = []
    mutex = threading.Lock()
    threads = []

    def _task(name: str, fn):
        try:
            items = fn(keyword)             # 各源的搜索函数
            with mutex:
                results.extend(items)
        except Exception as e:
            print(f"Error searching {name}: {e}")

    for name in sources:
        fn = SEARCHERS.get(name)
        if not fn:
            print(f"[WARN] 未找到搜索函数: {name}")
            continue
        t = threading.Thread(target=_task, args=(name, fn), daemon=True)
        threads.append(t)
        t.start()

        # 控制并发数，避免瞬间开太多线程
        while len([th for th in threads if th.is_alive()]) >= max_workers:
            for th in threads:
                th.join(timeout=0.1)

    # 等待剩余线程
    for t in threads:
        t.join()

    return results
