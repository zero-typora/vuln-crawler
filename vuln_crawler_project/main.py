import sys, datetime as dt, threading, traceback
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QTextEdit, QPushButton, QDateEdit, QLabel,
    QComboBox, QLineEdit, QMessageBox,QMenu
)
    # ←★ 新增 QTextCursor
import requests
from PyQt6.QtCore import QTimer, QMutex, pyqtSignal,Qt,QPoint
from PyQt6.QtGui import QColor,QTextCursor
from models import VulnItem
from utils import fetch_all, set_proxy, _session
import changtin, oscs, qianxin, threatbook, cisa
from poc_fetcher import fetch_poc_urls, set_github_token
from config_io import load_cfg, save_cfg
from html import escape
from PyQt6.QtCore import Qt, QMetaObject

FETCHERS = [
    changtin.fetch_changtin,
    oscs.fetch_oscs,
    qianxin.fetch_qianxin,
    threatbook.fetch_threatbook,
    cisa.fetch_cisa,
]
PAGE_SIZE = 30

SEV_COLOR = {
    "严重":   QColor("#c678dd"),   # 紫
    "极危":   QColor("#e06c75"),   # 红
    "高危":   QColor("#e5a742"),   # 橘
    "高风险": QColor("#61afef"),   # 蓝   ← ThreatBook
    "中危":   QColor("#d19a66"),   # 黄
}
class MainWindow(QMainWindow):
    data_ready = pyqtSignal(list)
    proxy_test_done = pyqtSignal(str)
    add_html = pyqtSignal(str)
    def __init__(self):
        super().__init__()
        # --- ① 改成“近似正方形” ---
        self.setWindowTitle("高价值漏洞采集 & 推送工具")
        self.resize(900, 900)  # ← 宽高一致即可，大小按需再调

        container = QWidget(self)
        self.setCentralWidget(container)
        root = QVBoxLayout(container)

        # ---------- 顶栏（拆成两行） ----------
        # 第一行：日期 / 刷新 / 重置 / Cookie
        bar1 = QHBoxLayout()
        self.date_edit = QDateEdit()
        self.date_edit.setDate(dt.date.today())
        self.date_edit.setCalendarPopup(True)
        bar1.addWidget(QLabel("选择日期:"))
        bar1.addWidget(self.date_edit)

        self.refresh_btn = QPushButton("刷新爬取")
        self.refresh_btn.clicked.connect(self.load_data)
        bar1.addWidget(self.refresh_btn)

        self.reset_btn = QPushButton("重置")
        self.reset_btn.clicked.connect(self.reset_view)
        bar1.addWidget(self.reset_btn)

        bar1.addSpacing(15)
        bar1.addWidget(QLabel("认证目标源:"))
        self.src_combo = QComboBox()
        self.src_combo.addItems(["ThreatBook", "GitHub"])  # ★ 多了 GitHub
        self.src_combo.currentIndexChanged.connect(self._on_src_change)
        bar1.addWidget(self.src_combo)
        self.auth_edit = QLineEdit()
        self.auth_edit.setFixedWidth(320)
        self.auth_edit.setPlaceholderText("粘贴整串 Cookie")  # 默认 ThreatBook
        bar1.addWidget(self.auth_edit)
        self.auth_btn = QPushButton("应用认证")
        self.auth_btn.clicked.connect(self.apply_auth)  # 同一个按钮
        bar1.addWidget(self.auth_btn)
        bar1.addStretch()
        root.addLayout(bar1)
        # 第二行：HTTP / HTTPS 代理（独占一行）
        bar2 = QHBoxLayout()
        bar2.addWidget(QLabel("HTTP 代理:"))
        self.http_edit = QLineEdit()
        self.http_edit.setFixedWidth(250)
        bar2.addWidget(self.http_edit)

        bar2.addWidget(QLabel("HTTPS 代理:"))
        self.https_edit = QLineEdit()
        self.https_edit.setFixedWidth(250)
        bar2.addWidget(self.https_edit)

        self.proxy_btn = QPushButton("应用代理")
        self.proxy_btn.clicked.connect(self.apply_proxy)
        bar2.addWidget(self.proxy_btn)

        self.test_btn = QPushButton("测试代理")
        self.test_btn.clicked.connect(self.test_proxy)
        bar2.addWidget(self.test_btn)

        bar2.addStretch()
        root.addLayout(bar2)

        # ---------- 表格 + 详情 ----------
        # ---------- 表格 + 详情 ----------
        mid = QHBoxLayout()

        # —— 左侧表格 ——
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["名称", "日期", "来源", "等级"])
        self.table.setSelectionBehavior(self.table.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(self.table.EditTrigger.NoEditTriggers)
        self.table.cellClicked.connect(self.show_detail)

        header = self.table.horizontalHeader()
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self.show_header_menu)

        mid.addWidget(self.table, 3)  # ← stretch 3

        # —— 右侧详情：QTextBrowser（可点链接） ——
        from PyQt6.QtWidgets import QTextBrowser  # 顶部 import 一并加上

        self.detail_box = QTextBrowser()
        self.detail_box.setReadOnly(True)  # 可省略，Browser 默认只读
        self.detail_box.setOpenExternalLinks(True)  # 允许点击直接在浏览器打开
        mid.addWidget(self.detail_box, 5)  # ← stretch 5

        root.addLayout(mid)
        # ---------- 分页 ----------
        nav = QHBoxLayout()
        self.prev_btn = QPushButton("上一页"); self.prev_btn.clicked.connect(lambda: self.change_page(-1))
        self.next_btn = QPushButton("下一页"); self.next_btn.clicked.connect(lambda: self.change_page(1))
        nav.addStretch(); nav.addWidget(self.prev_btn); nav.addWidget(self.next_btn)
        root.addLayout(nav)

        # ---------- 状态 ----------
        self.full_data: list[VulnItem] = []
        self.page = 0
        self._mtx = QMutex()
        self._click_token = 0  # ★ 点击计数器
        self.data_ready.connect(self.on_data_ready)
        self.add_html.connect(self._append_html)
        self.proxy_test_done.connect(self._show_proxy_msg)
        self.timer = QTimer()
        self.timer.timeout.connect(self.load_data)
        self.load_data()
        # ---------- 载入持久化的 GitHub Token ----------
        cfg = load_cfg()
        gh_token = cfg.get("github_token", "")
        if gh_token:
            set_github_token(gh_token)
            self.auth_edit.setText(gh_token)  # 如果你想启动时自动填入输入框
    # ---------- 右键列显示菜单 ----------
    def show_header_menu(self, pos):
        """
        在表头右键弹出可勾选列的菜单
        """
        header = self.table.horizontalHeader()
        headers = ["名称", "日期", "来源", "等级"]

        menu = QMenu(self)
        for idx, text in enumerate(headers):
            act = menu.addAction(text)
            act.setCheckable(True)
            act.setChecked(not header.isSectionHidden(idx))

            # 用默认实参把 idx 固定在 lambda 内
            act.toggled.connect(lambda checked, i=idx:
                                header.showSection(i) if checked else header.hideSection(i)
                                )
        menu.exec(header.mapToGlobal(pos))
    # ---------- 认证 ----------
    def _on_src_change(self):
        """切换 ThreatBook / GitHub 时更新占位提示"""
        if self.src_combo.currentText() == "GitHub":
            self.auth_edit.setPlaceholderText("粘贴 GitHub Token (PAT)")
        else:
            self.auth_edit.setPlaceholderText("粘贴整串 Cookie")

    def _append_html(self, html: str) -> None:
        cur = self.detail_box.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End) # 光标移到末尾
        cur.insertHtml(html)  # 追加富文本
        self.detail_box.setTextCursor(cur)  # 滚动到底
    def apply_auth(self):
        txt = self.auth_edit.text().strip()
        src = self.src_combo.currentText()

        if src == "ThreatBook":
            threatbook.set_cookie(txt)
        elif src == "GitHub":
            set_github_token(txt or None)
            cfg = load_cfg()
            if txt:
                cfg["github_token"] = txt
            else:
                cfg.pop("github_token", None)  # 清空输入框时同步删除
            save_cfg(cfg)
            print("[DEBUG] save_cfg called, cfg =", cfg)
        self._flash(self.auth_btn)

    # ---------- 代理 ----------
    def apply_proxy(self):
        set_proxy(self.http_edit.text().strip() or None,
                  self.https_edit.text().strip() or None)
        self._flash(self.proxy_btn)

    def test_proxy(self):
        http_url = self.http_edit.text().strip() or None
        https_url = self.https_edit.text().strip() or None

        def worker():
            s = requests.Session()
            from utils import _normalize
            http_proxy = _normalize(http_url, "http")
            https_proxy = _normalize(https_url, "http")
            s.proxies = {}
            if http_proxy:
                s.proxies["http"] = http_proxy
            if https_proxy:
                s.proxies["https"] = https_proxy

            try:
                r = s.get("http://httpbin.org/ip", timeout=5)
                r.raise_for_status()
                msg = f"代理可用，外网 IP: {r.json().get('origin')}"
            except Exception as e:
                msg = f"代理不可用：{e}"

            # 用信号把结果送回主线程
            self.proxy_test_done.emit(msg)

        threading.Thread(target=worker, daemon=True).start()
    def _show_proxy_msg(self, msg: str):
        box = QMessageBox(self)
        box.setWindowTitle("代理测试结果")
        box.setText(msg)
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.setStyleSheet(
            "QLabel{min-width:380px; max-width:380px; word-wrap:break-word;}"
        )
        box.exec()
    # ---------- 抓取 ----------
    def load_data(self):
        if not self._mtx.tryLock(): return
        self.refresh_btn.setEnabled(False)

        def worker():
            wanted = self.date_edit.date().toPyDate()
            data = []
            for i in range(7):
                day = (wanted - dt.timedelta(days=i)).isoformat()
                data = fetch_all(day, FETCHERS)
                if data: break
            self.data_ready.emit(data)
        threading.Thread(target=worker, daemon=True).start()

    def on_data_ready(self, data: list[VulnItem]):
        print("[GUI] got", len(data), "items")
        self.full_data = sorted(data, key=lambda x: x.name)
        self.page = 0; self.update_table()
        self.refresh_btn.setEnabled(True); self._mtx.unlock()
        if data and not self.timer.isActive():
            self.timer.start(30*60*1000)

    # ---------- UI ----------
    def _flash(self, btn: QPushButton):
        old = btn.text(); btn.setText("已更新")
        QTimer.singleShot(1500, lambda: btn.setText(old))

    def reset_view(self):
        self.detail_box.clear(); self.table.clearSelection()

    def update_table(self):
        start = self.page * PAGE_SIZE
        rows = self.full_data[start:start + PAGE_SIZE]

        self.table.setRowCount(len(rows))
        for r, v in enumerate(rows):
            for c, text in enumerate([v.name, v.date, v.source, v.severity or ""]):
                item = QTableWidgetItem(text)
                # 仅给“等级”列上色，也可换成整行
                if c == 3 and v.severity in SEV_COLOR:
                    item.setForeground(SEV_COLOR[v.severity])
                self.table.setItem(r, c, item)

        self.prev_btn.setEnabled(self.page > 0)
        self.next_btn.setEnabled(start + PAGE_SIZE < len(self.full_data))

    def change_page(self, d:int):
        self.page += d; self.update_table()

    def show_detail(self, row: int, _col: int):
        idx = self.page * PAGE_SIZE + row
        item = self.full_data[idx]

        # ---------- 基本信息 ----------
        self._click_token += 1
        tok = self._click_token
        html_base = "<br>".join(escape(item.display_block()).splitlines())
        self.detail_box.setHtml(html_base)

        # ---------- 后台搜 GitHub ----------
        def worker():
            try:
                urls = fetch_poc_urls(item.cve, item.name,
                                      item.cve or item.tags)[:2]
            except Exception as e:
                print("[PoC] err:", e)
                urls = []

            print(f"[PoC] {item.cve or item.name[:40]} -> {len(urls)} hit(s)")
            if not urls or tok != self._click_token:
                return

            links = "<br>".join(f'<a href="{u}">{u}</a>' for u in urls)
            poc_html = f"<br><b>[PoC/EXP]</b><br>{links}"
            print(poc_html)
            # ★ 直接发信号，由 _append_html 在主线程插入
            self.add_html.emit(poc_html)

        threading.Thread(target=worker, daemon=True).start()

def main() -> None:
    app = QApplication(sys.argv)
    win = MainWindow(); win.show()
    sys.exit(app.exec())
if __name__ == "__main__":
    main()
