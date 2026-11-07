import sys
import struct
import ctypes
import ctypes.wintypes as wt

from PySide6.QtCore import Qt, QTimer, QThread, Signal
from PySide6.QtGui import QFont, QIcon, QPixmap, QPainter, QColor, QPolygon, QPen
from PySide6.QtCore import QPoint
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QPushButton,
    QLineEdit, QComboBox, QLabel, QDialog, QListWidget, QListWidgetItem,
    QVBoxLayout, QHBoxLayout, QWidget, QInputDialog, QMessageBox, QCheckBox,
    QHeaderView, QAbstractItemView, QSplitter, QStyle)

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

ACCESS = 0x10 | 0x20 | 0x8 | 0x400
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
WRITABLE = (0x04, 0x08, 0x40, 0x80)


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),
                ("PartitionId", wt.WORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD),
                ("Protect", wt.DWORD),
                ("Type", wt.DWORD)]


class PROC32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_char * 260)]


def procs():
    snap = k32.CreateToolhelp32Snapshot(2, 0)
    e = PROC32()
    e.dwSize = ctypes.sizeof(e)
    out = []
    if k32.Process32First(snap, ctypes.byref(e)):
        while True:
            out.append((e.szExeFile.decode("mbcs", "replace"),
                        e.th32ProcessID))
            if not k32.Process32Next(snap, ctypes.byref(e)):
                break
    k32.CloseHandle(snap)
    return sorted(out)


def regions(h):
    out, addr = [], 0
    m = MBI()
    while k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(m),
                             ctypes.sizeof(m)):
        ba = m.BaseAddress or 0
        if (m.State == MEM_COMMIT and m.Protect in WRITABLE
                and m.Type == MEM_PRIVATE and m.RegionSize > 0):
            out.append((ba, m.RegionSize))
        nxt = ba + m.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return out


def rmem(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n,
                                 ctypes.byref(got)):
        return None
    return buf.raw[:got.value]


def wmem(h, addr, data):
    got = ctypes.c_size_t(0)
    return bool(k32.WriteProcessMemory(h, ctypes.c_void_p(addr), data,
                                       len(data), ctypes.byref(got)))


TYPES = {"4 bytes": ("<i", 4), "8 bytes": ("<q", 8),
         "float": ("<f", 4), "double": ("<d", 8), "byte": ("<b", 1)}
FILTERS = ["exact", "increased", "decreased", "changed", "unchanged"]
CHUNK = 4 * 1024 * 1024


def pack_val(fmt, text):
    if fmt in ("<f", "<d"):
        return struct.pack(fmt, float(text))
    return struct.pack(fmt, int(text, 0))


class Scan(QThread):
    count = Signal(int)
    done = Signal(dict)

    def __init__(self, h, regs, first, fmt, pat=None, prev=None, fmode=None):
        super().__init__()
        self.h, self.regs, self.first = h, regs, first
        self.fmt, self.pat, self.prev, self.fmode = fmt, pat, prev, fmode

    def _keep(self, old, new):
        if self.fmode == "increased":
            return new > old
        if self.fmode == "decreased":
            return new < old
        if self.fmode == "changed":
            return new != old
        if self.fmode == "unchanged":
            return new == old
        return new == self._target

    def run(self):
        hits = {}
        size = struct.calcsize(self.fmt)
        if not self.first:
            self._target = struct.unpack(
                self.fmt, self.pat)[0] if self.fmode == "exact" else None
        for base, rs in self.regs:
            hits_r = [a for a in self.prev] if not self.first else None
            pos = 0
            while pos < rs:
                n = min(rs - pos, CHUNK)
                data = rmem(self.h, base + pos, n)
                if data is None:
                    pos += n
                    continue
                if self.first:
                    off = 0
                    while True:
                        off = data.find(self.pat, off)
                        if off < 0:
                            break
                        hits[base + pos + off] = struct.unpack(
                            self.fmt, data[off:off + size])[0]
                        off += 1
                else:
                    for a in hits_r:
                        if base + pos <= a < base + pos + len(data) - size + 1:
                            o = a - base - pos
                            v = struct.unpack(
                                self.fmt, data[o:o + size])[0]
                            if self._keep(self.prev[a], v):
                                hits[a] = v
                pos += n
            self.count.emit(len(hits))
        self.done.emit(hits)


def mk_icon():
    px = QPixmap(16, 16)
    px.fill(Qt.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(QPen(QColor("#2255aa"), 1))
    p.setBrush(QColor("#7fb0e8"))
    p.drawRect(1, 4, 9, 8)
    for i in (2, 5, 8):
        p.drawLine(i, 2, i, 4)
        p.drawLine(i, 12, i, 14)
    p.setPen(QPen(QColor("#c06000"), 2))
    p.setBrush(QColor(255, 220, 150, 140))
    p.drawEllipse(7, 6, 7, 7)
    p.drawLine(12, 12, 15, 15)
    p.end()
    return QIcon(px)


class ProcDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("select process")
        self.resize(340, 380)
        lay = QVBoxLayout(self)
        self.finder = QLineEdit()
        self.finder.setPlaceholderText("filter by name")
        lay.addWidget(self.finder)
        self.lst = QListWidget()
        lay.addWidget(self.lst)
        for name, pid in procs():
            it = QListWidgetItem("%s  (%d)" % (name, pid))
            it.setData(Qt.UserRole, pid)
            self.lst.addItem(it)
        self.lst.sortItems()
        self.lst.itemDoubleClicked.connect(self.accept)
        self.finder.textChanged.connect(self._filt)
        self.pick = None

    def _filt(self, t):
        for i in range(self.lst.count()):
            it = self.lst.item(i)
            it.setHidden(t.lower() not in it.text().lower())

    def accept(self):
        it = self.lst.currentItem()
        if it:
            self.pick = (it.text().split("  (")[0],
                         it.data(Qt.UserRole))
        super().accept()


class Win(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("peek")
        self.setWindowIcon(mk_icon())
        self.resize(720, 560)
        self.h = None
        self.pid = None
        self.regs = []
        self.hits = {}
        self.scan = None

        top = QWidget()
        tl = QHBoxLayout(top)
        tl.setContentsMargins(6, 6, 6, 2)
        self.pbtn = QPushButton(self.style().standardIcon(
            QStyle.SP_ComputerIcon), " select process")
        self.pname = QLabel("none")
        self.pname.setStyleSheet("font-weight:bold;")
        tl.addWidget(self.pbtn)
        tl.addWidget(self.pname)
        tl.addStretch(1)
        tl.addWidget(QLabel("value type:"))
        self.vt = QComboBox()
        self.vt.addItems(list(TYPES))
        tl.addWidget(self.vt)

        mid = QWidget()
        ml = QHBoxLayout(mid)
        ml.setContentsMargins(6, 0, 6, 2)
        ml.addWidget(QLabel("scan:"))
        self.fmode = QComboBox()
        self.fmode.addItems(FILTERS)
        ml.addWidget(self.fmode)
        self.val = QLineEdit()
        self.val.setPlaceholderText("value")
        ml.addWidget(self.val)
        self.first_btn = QPushButton("first scan")
        self.next_btn = QPushButton("next scan")
        self.next_btn.setEnabled(False)
        self.new_btn = QPushButton("new scan")
        ml.addWidget(self.first_btn)
        ml.addWidget(self.next_btn)
        ml.addWidget(self.new_btn)
        self.found_lbl = QLabel("found: 0")
        ml.addStretch(1)
        ml.addWidget(self.found_lbl)

        self.res = QTableWidget(0, 2)
        self.res.setHorizontalHeaderLabels(["address", "value"])
        self.res.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch)
        self.res.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.res.setEditTriggers(QAbstractItemView.NoEditTriggers)

        self.addr = QTableWidget(0, 5)
        self.addr.setHorizontalHeaderLabels(
            ["", "description", "address", "type", "value"])
        self.addr.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch)
        self.addr.setColumnWidth(0, 24)

        split = QSplitter(Qt.Vertical)
        split.addWidget(self.res)
        split.addWidget(self.addr)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)

        c = QWidget()
        cl = QVBoxLayout(c)
        cl.setContentsMargins(2, 2, 2, 2)
        cl.addWidget(top)
        cl.addWidget(mid)
        cl.addWidget(split)
        self.setCentralWidget(c)

        add = QPushButton("add selected")
        ml.addWidget(add)

        self.pbtn.clicked.connect(self.attach)
        self.first_btn.clicked.connect(self.first_scan)
        self.next_btn.clicked.connect(lambda: self.scan_now(False))
        self.new_btn.clicked.connect(self.reset)
        add.clicked.connect(self.add_addr)
        self.res.itemDoubleClicked.connect(
            lambda it: self.add_addr())
        self.addr.itemChanged.connect(self._addr_edit)
        self.addr.itemDoubleClicked.connect(self._desc_edit)

        self.freeze = QTimer(self)
        self.freeze.setInterval(300)
        self.freeze.timeout.connect(self._freeze_tick)
        self.watch = QTimer(self)
        self.watch.setInterval(500)
        self.watch.timeout.connect(self._watch_tick)
        self.watch.start()
        self.statusBar().showMessage("pick a process")

    def attach(self):
        d = ProcDialog(self)
        if d.exec() and d.pick:
            name, pid = d.pick
            h = k32.OpenProcess(ACCESS, False, pid)
            if not h:
                QMessageBox.warning(
                    self, "peek",
                    "cant open %s (pid %d) - error %d" % (
                        name, pid, ctypes.get_last_error()))
                return
            if self.h:
                k32.CloseHandle(self.h)
            self.h, self.pid = h, pid
            self.pname.setText("%s  pid %d" % (name, pid))
            self.regs = regions(h)
            self.reset()
            self.statusBar().showMessage(
                "attached - %d writable regions" % len(self.regs))

    def _cur(self):
        return TYPES[self.vt.currentText()]

    def first_scan(self):
        self.scan_now(True)

    def scan_now(self, first):
        if not self.h or (self.scan and self.scan.isRunning()):
            return
        fmt, size = self._cur()
        try:
            pat = pack_val(fmt, self.val.text().strip())
        except Exception:
            if self.fmode.currentText() in ("increased", "decreased",
                                            "changed", "unchanged") \
                    and not first:
                pat = None
            else:
                self.statusBar().showMessage("bad value")
                return
        self.first_btn.setEnabled(False)
        self.next_btn.setEnabled(False)
        self.statusBar().showMessage("scanning...")
        self.scan = Scan(self.h, self.regs, first, fmt, pat,
                         self.hits if not first else None,
                         self.fmode.currentText())
        self.scan.count.connect(
            lambda n: self.found_lbl.setText("found: %d" % n))
        self.scan.done.connect(self._scan_done)
        self.scan.start()

    def _scan_done(self, hits):
        self.hits = hits
        self.first_btn.setEnabled(True)
        self.next_btn.setEnabled(True)
        self.found_lbl.setText("found: %d" % len(hits))
        self.res.blockSignals(True)
        show = list(hits.items())[:500]
        self.res.setRowCount(len(show))
        for i, (a, v) in enumerate(show):
            self.res.setItem(i, 0, QTableWidgetItem("%08X" % a))
            self.res.setItem(i, 1, QTableWidgetItem(
                ("%g" % v) if isinstance(v, float) else str(v)))
        self.res.blockSignals(False)
        self.statusBar().showMessage(
            "done - %d results%s" % (
                len(hits), " (showing 500)" if len(hits) > 500 else ""))

    def reset(self):
        self.hits = {}
        self.res.setRowCount(0)
        self.found_lbl.setText("found: 0")
        self.next_btn.setEnabled(False)
        self.statusBar().showMessage("ready")

    def add_addr(self):
        r = self.res.currentRow()
        if r < 0:
            return
        a = int(self.res.item(r, 0).text(), 16)
        fmt, size = self._cur()
        row = self.addr.rowCount()
        self.addr.blockSignals(True)
        self.addr.insertRow(row)
        chk = QTableWidgetItem("")
        chk.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
        chk.setCheckState(Qt.Unchecked)
        self.addr.setItem(row, 0, chk)
        self.addr.setItem(row, 1, QTableWidgetItem("no description"))
        it_a = QTableWidgetItem("%08X" % a)
        it_a.setFlags(it_a.flags() & ~Qt.ItemIsEditable)
        self.addr.setItem(row, 2, it_a)
        it_t = QTableWidgetItem(self.vt.currentText())
        it_t.setFlags(it_t.flags() & ~Qt.ItemIsEditable)
        self.addr.setItem(row, 3, it_t)
        self.addr.setItem(row, 4, QTableWidgetItem("?"))
        self.addr.blockSignals(False)

    def _addr_edit(self, it):
        if it.column() == 4 and self.h:
            row = it.row()
            a = int(self.addr.item(row, 2).text(), 16)
            fmt, size = TYPES[self.addr.item(row, 3).text()]
            try:
                wmem(self.h, a, pack_val(fmt, it.text().strip()))
            except Exception:
                pass

    def _desc_edit(self, it):
        if it.column() == 1:
            txt, ok = QInputDialog.getText(
                self, "description", "name:",
                text=it.text())
            if ok:
                it.setText(txt)

    def _row_addr(self, row):
        return int(self.addr.item(row, 2).text(), 16)

    def _freeze_tick(self):
        if not self.h:
            return
        for r in range(self.addr.rowCount()):
            chk = self.addr.item(r, 0)
            if chk and chk.checkState() == Qt.Checked:
                fmt, size = TYPES[self.addr.item(r, 3).text()]
                v = self.addr.item(r, 4).text()
                try:
                    wmem(self.h, self._row_addr(r),
                         pack_val(fmt, v))
                except Exception:
                    pass

    def _watch_tick(self):
        if not self.h or (self.scan and self.scan.isRunning()):
            return
        for r in range(self.addr.rowCount()):
            fmt, size = TYPES[self.addr.item(r, 3).text()]
            data = rmem(self.h, self._row_addr(r), size)
            if data and len(data) == size:
                v = struct.unpack(fmt, data)[0]
                cur = self.addr.item(r, 4)
                s = ("%g" % v) if isinstance(v, float) else str(v)
                if cur.text() != s:
                    self.addr.blockSignals(True)
                    cur.setText(s)
                    self.addr.blockSignals(False)

    def closeEvent(self, e):
        if self.h:
            k32.CloseHandle(self.h)
        e.accept()


def launch():
    app = QApplication(sys.argv)
    app.setStyle("windowsvista")
    app.setFont(QFont("Tahoma", 8))
    app.setStyleSheet("""
        QMainWindow, QDialog { background: #ece9d8; }
        QPushButton { padding: 3px 10px; }
        QLineEdit, QComboBox, QListWidget, QTableWidget {
            background: #fff; border: 1px solid #7f9db9; }
        QHeaderView::section { background: #ece9d8; border: 0;
            border-right: 1px solid #aca899;
            border-bottom: 1px solid #aca899; padding: 3px; }
        QStatusBar { background: #ece9d8;
            border-top: 1px solid #aca899; }
    """)
    w = Win()
    w.show()
    if "--shot" in sys.argv:
        def snap():
            w.grab().toImage().save("shot.png")
            app.quit()
        QTimer.singleShot(2500, snap)
    app.exec()


if __name__ == "__main__":
    launch()
