# demo_poc_inject.py  ── PyQt6 ≥ 6.2
import sys, threading, time, random
from PyQt6.QtWidgets import (
    QApplication, QWidget, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QTextBrowser
)
from PyQt6.QtCore import QTimer
from html import escape

# ── 假数据，两行表 + 两个“检索到的”URL ────────────────────────────
ROWS = [
    {"name": "Kafka Connect 任意文件读取漏洞", "cve": "CVE-2025-27817"},
    {"name": "GeoServer XXE 注入漏洞",      "cve": "CVE-2025-24016"},
]
FAKE_URLS = [
    "https://github.com/xxxx/PoC1.md",
    "https://github.com/xxxx/PoC2.md"
]

class Demo(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PoC Demo"); self.resize(860, 460)

        lay = QHBoxLayout(self)
        self.tbl = QTableWidget(len(ROWS), 2); lay.addWidget(self.tbl, 1)
        self.box = QTextBrowser(); self.box.setOpenExternalLinks(True)
        lay.addWidget(self.box, 2)

        self.tbl.setHorizontalHeaderLabels(["漏洞名称", "CVE"])
        for r, row in enumerate(ROWS):
            self.tbl.setItem(r, 0, QTableWidgetItem(row["name"]))
            self.tbl.setItem(r, 1, QTableWidgetItem(row["cve"]))

        self.tbl.cellClicked.connect(self.show_detail)
        self._click_token = 0    # 点击计数

    # 主逻辑只看这一函数 ↓↓↓↓↓↓↓↓↓
    def show_detail(self, row:int, _col:int):
        self._click_token += 1
        tok = self._click_token
        vuln = ROWS[row]

        # ①   纯文本 → HTML (<br>)
        base_html = "<br>".join(escape(
            f"【漏洞名称】{vuln['name']}\n【CVE】{vuln['cve']}\n【poc/exp】"
        ).splitlines())
        self.box.setHtml(base_html)           # 一次性写入

        # ②   后台“检索”——这里睡 1-2 秒后返回假 URL
        def worker():
            time.sleep(random.uniform(1, 2))
            urls = FAKE_URLS                  # 只演示
            links = "<br>".join(f'<a href="{u}">{u}</a>' for u in urls)
            poc_html = f"<br><b>[PoC/EXP]</b><br>{links}"

            def append():
                if tok == self._click_token:  # 行没换
                    self.box.append(poc_html) # 关键：append 富文本

            QTimer.singleShot(0, append)      # 回到主线程

        threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    Demo().show(); sys.exit(app.exec())
