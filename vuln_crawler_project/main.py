import sys
import datetime as dt
import threading
import traceback

import requests
from PyQt6.QtCore import (
    Qt,
    QTimer,
    QMutex,
    pyqtSignal,
)
from PyQt6.QtGui import QColor, QTextCursor
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QLabel,
    QPushButton,
    QLineEdit,
    QDateEdit,
    QMessageBox,
    QComboBox,
    QMenu,
    QTextBrowser,
)

from models import VulnItem
from utils import fetch_all, set_proxy, _session  # noqa: F401 – _session might be unused directly here
import changtin
import oscs
import qianxin
import threatbook
import cisa
from poc_fetcher import fetch_poc_urls, set_github_token
from config_io import load_cfg, save_cfg
from html import escape
from vuln_search import search_vulns

# ---------------------------------------------------------------------------
# 常量配置
# ---------------------------------------------------------------------------
DATE_FETCHERS = [
    changtin.fetch_changtin,
    oscs.fetch_oscs,
    qianxin.fetch_qianxin,
    threatbook.fetch_threatbook,
    cisa.fetch_cisa,
]
PAGE_SIZE = 30

SEV_COLOR = {
    "严重": QColor("#c678dd"),  # 紫
    "极危": QColor("#e06c75"),  # 红
    "高危": QColor("#e5a742"),  # 橘
    "高风险": QColor("#61afef"),  # 蓝（ThreatBook）
    "中危": QColor("#d19a66"),  # 黄
}


# ---------------------------------------------------------------------------
# 主窗口
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    data_ready = pyqtSignal(list)
    proxy_test_done = pyqtSignal(str)
    add_html = pyqtSignal(str)
    search_finished = pyqtSignal(list)

    # ---------------------------------------------------------------------
    # 初始化
    # ---------------------------------------------------------------------
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("高价值漏洞采集 & 推送工具by运维仔")
        self.resize(1000, 900)

        container = QWidget(self)
        self.setCentralWidget(container)
        root = QVBoxLayout(container)

        # --------------------------------------------------------------
        # 顶栏（2 行 × 2 功能区）
        # --------------------------------------------------------------
        # 行 1：日期范围 + 刷新/重置 + 搜索
        bar_top1 = QHBoxLayout()

        # -- 日期范围 --
        self.date_from = QDateEdit(calendarPopup=True)
        self.date_from.setDate(dt.date.today() - dt.timedelta(days=2))
        bar_top1.addWidget(QLabel("起始日期:"))
        bar_top1.addWidget(self.date_from)

        self.date_to = QDateEdit(calendarPopup=True)
        self.date_to.setDate(dt.date.today())
        bar_top1.addWidget(QLabel("结束日期:"))
        bar_top1.addWidget(self.date_to)

        self.refresh_btn = QPushButton("刷新爬取")
        self.refresh_btn.clicked.connect(self.load_data)
        bar_top1.addWidget(self.refresh_btn)

        self.reset_btn = QPushButton("重置")
        self.reset_btn.clicked.connect(self.reset_view)
        bar_top1.addWidget(self.reset_btn)

        bar_top1.addSpacing(20)

        # -- 搜索 --
        bar_top1.addWidget(QLabel("漏洞搜索:"))
        self.search_edit = QLineEdit()
        self.search_edit.setFixedWidth(300)
        self.search_edit.setPlaceholderText("输入 CVE 编号或漏洞名称")
        bar_top1.addWidget(self.search_edit)

        self.search_btn = QPushButton("搜索")
        self.search_btn.clicked.connect(self.search_vulns_gui)
        bar_top1.addWidget(self.search_btn)

        bar_top1.addStretch()
        root.addLayout(bar_top1)

        # 行 2：认证 + 代理
        bar_top2 = QHBoxLayout()

        # -- 认证 --
        bar_top2.addWidget(QLabel("认证目标源:"))
        self.src_combo = QComboBox()
        self.src_combo.addItems(["ThreatBook", "GitHub"])
        self.src_combo.currentIndexChanged.connect(self._on_src_change)
        bar_top2.addWidget(self.src_combo)

        self.auth_edit = QLineEdit()
        self.auth_edit.setFixedWidth(320)
        self.auth_edit.setPlaceholderText("粘贴整串 Cookie")
        bar_top2.addWidget(self.auth_edit)

        self.auth_btn = QPushButton("应用认证")
        self.auth_btn.clicked.connect(self.apply_auth)
        bar_top2.addWidget(self.auth_btn)

        bar_top2.addSpacing(30)

        # -- 代理 --
        bar_top2.addWidget(QLabel("HTTP 代理:"))
        self.http_edit = QLineEdit()
        self.http_edit.setFixedWidth(180)
        bar_top2.addWidget(self.http_edit)

        bar_top2.addWidget(QLabel("HTTPS 代理:"))
        self.https_edit = QLineEdit()
        self.https_edit.setFixedWidth(180)
        bar_top2.addWidget(self.https_edit)

        self.proxy_btn = QPushButton("应用代理")
        self.proxy_btn.clicked.connect(self.apply_proxy)  # ★ 修复未绑定
        bar_top2.addWidget(self.proxy_btn)

        self.test_btn = QPushButton("测试代理")
        self.test_btn.clicked.connect(self.test_proxy)  # ★ 修复未绑定
        bar_top2.addWidget(self.test_btn)

        bar_top2.addStretch()
        root.addLayout(bar_top2)

        # --------------------------------------------------------------
        # 中部：表格 + 详情
        # --------------------------------------------------------------
        mid = QHBoxLayout()

        # 表格
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["名称", "日期", "来源", "等级"])
        self.table.setSelectionBehavior(self.table.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(self.table.EditTrigger.NoEditTriggers)
        self.table.cellClicked.connect(self.show_detail)

        header = self.table.horizontalHeader()
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self.show_header_menu)

        mid.addWidget(self.table, 3)

        # 详情
        self.detail_box = QTextBrowser()
        self.detail_box.setOpenExternalLinks(True)
        mid.addWidget(self.detail_box, 5)

        root.addLayout(mid)

        # --------------------------------------------------------------
        # 分页
        # --------------------------------------------------------------
        nav = QHBoxLayout()
        self.prev_btn = QPushButton("上一页")
        self.prev_btn.clicked.connect(lambda: self.change_page(-1))
        self.next_btn = QPushButton("下一页")
        self.next_btn.clicked.connect(lambda: self.change_page(1))
        nav.addStretch()
        nav.addWidget(self.prev_btn)
        nav.addWidget(self.next_btn)
        root.addLayout(nav)

        # --------------------------------------------------------------
        # 运行时状态
        # --------------------------------------------------------------
        self.full_data: list[VulnItem] = []
        self.page = 0
        self._mtx = QMutex()
        self._click_token = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.load_data)

        # 关联信号
        self.data_ready.connect(self.on_data_ready)
        self.add_html.connect(self._append_html)
        self.proxy_test_done.connect(self._show_proxy_msg)
        self.search_finished.connect(self.handle_search_results)

        # 首次加载数据
        self.load_data()

        # 读取保存的 GitHub Token
        cfg = load_cfg()
        if token := cfg.get("github_token"):
            set_github_token(token)
            self.auth_edit.setText(token)

    # ------------------------------------------------------------------
    # 表头右键菜单：显示/隐藏列
    # ------------------------------------------------------------------
    def show_header_menu(self, pos):
        header = self.table.horizontalHeader()
        titles = ["名称", "日期", "来源", "等级"]
        menu = QMenu(self)
        for idx, title in enumerate(titles):
            act = menu.addAction(title)
            act.setCheckable(True)
            act.setChecked(not header.isSectionHidden(idx))
            act.toggled.connect(lambda chk, i=idx: header.showSection(i) if chk else header.hideSection(i))
        menu.exec(header.mapToGlobal(pos))

    # ------------------------------------------------------------------
    # 认证相关
    # ------------------------------------------------------------------
    def _on_src_change(self):
        hint = "粘贴 GitHub Token (PAT)" if self.src_combo.currentText() == "GitHub" else "粘贴整串 Cookie"
        self.auth_edit.setPlaceholderText(hint)

    def apply_auth(self):
        txt = self.auth_edit.text().strip()
        src = self.src_combo.currentText()

        if src == "ThreatBook":
            threatbook.set_cookie(txt)
        else:  # GitHub
            set_github_token(txt or None)
            cfg = load_cfg()
            if txt:
                cfg["github_token"] = txt
            else:
                cfg.pop("github_token", None)
            save_cfg(cfg)
        self._flash(self.auth_btn)

    # ------------------------------------------------------------------
    # 代理相关
    # ------------------------------------------------------------------
    def apply_proxy(self):
        set_proxy(self.http_edit.text().strip() or None, self.https_edit.text().strip() or None)
        self._flash(self.proxy_btn)

    def test_proxy(self):
        http_url = self.http_edit.text().strip() or None
        https_url = self.https_edit.text().strip() or None

        def worker():
            s = requests.Session()
            from utils import _normalize

            http_proxy = _normalize(http_url, "http")
            https_proxy = _normalize(https_url, "https")
            if http_proxy:
                s.proxies["http"] = http_proxy
            if https_proxy:
                s.proxies["https"] = https_proxy

            try:
                r = s.get("http://httpbin.org/ip", timeout=5)
                r.raise_for_status()
                msg = f"代理可用，外网 IP: {r.json().get('origin')}"
            except Exception as exc:
                msg = f"代理不可用：{exc}"

            self.proxy_test_done.emit(msg)

        threading.Thread(target=worker, daemon=True).start()

    def _show_proxy_msg(self, msg: str):
        QMessageBox.information(self, "代理测试结果", msg)

    # ------------------------------------------------------------------
    # 搜索
    # ------------------------------------------------------------------
    def search_vulns_gui(self):
        keyword = self.search_edit.text().strip()
        if not keyword:
            QMessageBox.warning(self, "输入错误", "请输入要搜索的 CVE 编号或漏洞名称！")
            return

        # ① 若定时刷新正在运行，先暂停
        if self.timer.isActive():
            self.timer.stop()

        # ② 清空现有表格和详情（无论 timer 是否在运行，都要清一次）
        self.full_data.clear()
        self.table.setRowCount(0)
        self.detail_box.clear()

        # ③ 置灰按钮，防止重复点击
        self.refresh_btn.setEnabled(False)
        self.search_btn.setEnabled(False)

        # ④ 开线程执行实际搜索
        def worker():
            vulns = search_vulns(keyword)  # ⬅️ 调用统一搜索入口
            self.search_finished.emit(vulns)

        threading.Thread(target=worker, daemon=True).start()

    def handle_search_results(self, vulns):
        self.refresh_btn.setEnabled(True)
        self.search_btn.setEnabled(True)

        if not vulns:
            QMessageBox.information(self, "无结果", "未找到匹配的漏洞！")
            # 搜索无结果也恢复定时刷新
            if not self.timer.isActive():
                self.timer.start(30 * 60 * 1000)
            return

        self.full_data = vulns
        self.page = 0
        self.update_table()
    # ------------------------------------------------------------------
    # 数据抓取
    # ------------------------------------------------------------------
    def load_data(self):
        if not self._mtx.tryLock():
            return

        self.refresh_btn.setEnabled(False)

        start_date = self.date_from.date().toPyDate()
        end_date = self.date_to.date().toPyDate()
        if start_date > end_date:
            QMessageBox.warning(self, "日期错误", "起始日期不能晚于结束日期！")
            self.refresh_btn.setEnabled(True)
            self._mtx.unlock()
            return

        def worker():
            data: list[VulnItem] = []
            cursor = start_date
            while cursor <= end_date:
                day_str = cursor.isoformat()
                data.extend(fetch_all(day_str, DATE_FETCHERS))
                cursor += dt.timedelta(days=1)
            self.data_ready.emit(data)

        threading.Thread(target=worker, daemon=True).start()

    def on_data_ready(self, data: list[VulnItem]):
        self.full_data = sorted(data, key=lambda v: v.name)
        self.page = 0
        self.update_table()
        self.refresh_btn.setEnabled(True)
        self._mtx.unlock()
        if data and not self.timer.isActive():
            self.timer.start(30 * 60 * 1000)  # 30‑min auto‑refresh

    # ------------------------------------------------------------------
    # UI 辅助
    # ------------------------------------------------------------------
    def _flash(self, btn: QPushButton):
        old = btn.text()
        btn.setText("已更新")
        QTimer.singleShot(1500, lambda: btn.setText(old))

    def reset_view(self):
        self.detail_box.clear()
        self.table.clearSelection()

    def update_table(self):
        start = self.page * PAGE_SIZE
        rows = self.full_data[start : start + PAGE_SIZE]

        self.table.setRowCount(len(rows))
        for r, v in enumerate(rows):
            for c, text in enumerate([v.name, v.date, v.source, v.severity or ""]):
                itm = QTableWidgetItem(text)
                if c == 3 and v.severity in SEV_COLOR:
                    itm.setForeground(SEV_COLOR[v.severity])
                self.table.setItem(r, c, itm)

        self.prev_btn.setEnabled(self.page > 0)
        self.next_btn.setEnabled(start + PAGE_SIZE < len(self.full_data))

    def change_page(self, delta: int):
        self.page += delta
        self.update_table()

    # ------------------------------------------------------------------
    # 详情
    # ------------------------------------------------------------------
    def _append_html(self, html: str):
        cursor = self.detail_box.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertHtml(html)
        self.detail_box.setTextCursor(cursor)

    def show_detail(self, row: int, _col: int):
        idx = self.page * PAGE_SIZE + row
        item = self.full_data[idx]

        # 基本信息
        self._click_token += 1
        token = self._click_token
        self.detail_box.setHtml("<br>".join(escape(item.display_block()).splitlines()))

        # 异步搜索 GitHub PoC
        def worker():
            try:
                urls = fetch_poc_urls(item.cve, item.name, item.cve or item.tags)[:2]
            except Exception as exc:
                print("[PoC] error:", exc)
                urls = []
            if not urls or token != self._click_token:
                return
            links = "<br>".join(f'<a href="{u}">{u}</a>' for u in urls)
            self.add_html.emit(f"<br><b>[PoC/EXP]</b><br>{links}")

        threading.Thread(target=worker, daemon=True).start()


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------

def main() -> None:
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
