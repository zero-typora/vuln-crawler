# ── config_io.py ─────────────────────────────────────────
"""
把 GitHub Token 等配置保存在 **当前程序目录**：
    ./vuln_crawler_config.json
"""

import json
from pathlib import Path

# 文件就在启动目录（通常就是你的 main.py 所在目录）
CFG_FILE = Path.cwd() / "vuln_crawler_config.json"


def load_cfg() -> dict:
    """读取配置，失败返回空 dict"""
    try:
        if CFG_FILE.exists():
            return json.loads(CFG_FILE.read_text())
    except Exception as e:
        print("[cfg] load error:", e)
    return {}


def save_cfg(d: dict):
    """写配置到当前目录"""
    try:
        CFG_FILE.write_text(json.dumps(d, ensure_ascii=False, indent=2))
        print(f"[cfg] saved → {CFG_FILE}")
    except Exception as e:
        print("[cfg] save error:", e)

