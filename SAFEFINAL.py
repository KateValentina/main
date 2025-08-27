
from __future__ import annotations

"""
Safe RDP Access Auditor (Non-bruteforce) — v10 SAFE FINAL
- Engines menu + "Use ALL Engines"
- Real engines kept: PyRDP+FreeRDP, FreeRDP (direct)
- Stub engines (safe): Impacket, RDPY3, MsRdpClient
- Domain/Workgroup removed entirely
- Results include 'Engine' column
- Finish handlers in all tabs reset buttons/progress
"""

import ipaddress
import socket
import sys
import threading
import time
import csv
import hashlib
import os
import subprocess
import signal
import shutil
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Set, Dict
from pathlib import Path

from PySide6.QtCore import (Qt, QObject, Signal, Slot, QThreadPool, QRunnable,
                            QMutex, QWaitCondition)
from PySide6.QtGui import QPalette, QColor
from PySide6.QtWidgets import (
    QApplication, QWidget, QMainWindow, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QLineEdit, QFileDialog, QSpinBox, QCheckBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QProgressBar,
    QListWidget, QListWidgetItem, QFormLayout, QGroupBox, QStatusBar, QComboBox
)

# ------------------------------ Utilities ------------------------------

ENGINE_NAMES = [
    "PyRDP+FreeRDP",
    "FreeRDP (direct)",
    "Impacket",
    "RDPY3",
    "MsRdpClient",
]

def log_hash(label: str, username: str, password: str, salt: str = "safe_salt") -> str:
    h = hashlib.sha256()
    h.update((label + "|" + username + "|" + password + "|" + salt).encode())
    return "sha256:" + h.hexdigest()


def expand_ip_token(token: str) -> List[str]:
    token = token.strip()
    ips: List[str] = []
    if not token:
        return ips
    try:
        if "/" in token:  # CIDR
            net = ipaddress.ip_network(token, strict=False)
            ips = [str(ip) for ip in net.hosts()]
        elif "-" in token:  # Range
            start, end = token.split("-", 1)
            start_ip = ipaddress.ip_address(start.strip())
            end_ip = ipaddress.ip_address(end.strip())
            if int(end_ip) < int(start_ip):
                start_ip, end_ip = end_ip, start_ip
            ips = [str(ipaddress.ip_address(i)) for i in range(int(start_ip), int(end_ip) + 1)]
        else:  # single
            ipaddress.ip_address(token)  # validate
            ips = [token]
    except Exception:
        ips = []
    return ips


# ------------------------------ Worker Base ------------------------------

class CancellableWorker(QRunnable):
    def __init__(self):
        super().__init__()
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._pause.clear()
        self.mutex = QMutex()
        self.cond = QWaitCondition()

    def stop(self):
        self._stop.set()
        self.resume()

    def pause(self):
        self._pause.set()

    def resume(self):
        if self._pause.is_set():
            self._pause.clear()
            self.cond.wakeAll()

    def should_stop(self) -> bool:
        return self._stop.is_set()

    def wait_if_paused(self):
        if self._pause.is_set():
            self.mutex.lock()
            try:
                while self._pause.is_set() and not self._stop.is_set():
                    self.cond.wait(self.mutex, 200)
            finally:
                self.mutex.unlock()


# ------------------------------ Signals & Settings ------------------------------

class Bus(QObject):
    log = Signal(str)
    progress = Signal(int)      # 0..100
    finished = Signal(str)      # message
    table_row = Signal(list)    # validation results
    good_ip = Signal(str)       # IP:Port found
    status = Signal(str)        # for status bar
    apply_settings = Signal()   # notify tabs to refresh from global settings


@dataclass
class GlobalSettings:
    threads: int = 100
    timeout_ms: int = 1000
    use_proxy: bool = False
    max_creds: int = 5  # 0 = No limit


# ------------------------------ Port Scan ------------------------------

@dataclass
class ScanConfig:
    ports: List[int] = field(default_factory=lambda: [3389, 3388, 3399, 3390, 3391, 3392])
    timeout_ms: int = 1000
    threads: int = 100
    realtime_save: bool = True
    realtime_path: str = "Good_IPS.txt"


class PortScanWorker(CancellableWorker):
    def __init__(self, bus: Bus, ips: List[str], cfg: ScanConfig):
        super().__init__()
        self.bus = bus
        self.ips = ips
        self.cfg = cfg
        self.total = max(1, len(self.ips) * len(self.cfg.ports))
        self.done = 0
        self._saved_set: Set[str] = set()
        if self.cfg.realtime_save and os.path.exists(self.cfg.realtime_path):
            try:
                with open(self.cfg.realtime_path, "r", encoding="utf-8") as f:
                    self._saved_set = {l.strip() for l in f if l.strip()}
            except Exception:
                self._saved_set = set()
        self._io_lock = threading.Lock()

    def try_connect(self, host: str, port: int) -> bool:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.cfg.timeout_ms / 1000.0)
        try:
            s.connect((host, port))
            return True
        except Exception:
            return False
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _save_realtime(self, ipport: str):
        if not self.cfg.realtime_save:
            return
        with self._io_lock:
            if ipport in self._saved_set:
                return
            try:
                with open(self.cfg.realtime_path, "a", encoding="utf-8") as f:
                    f.write(ipport + "\n")
                self._saved_set.add(ipport)
            except Exception:
                pass

    def run(self):
        lock = threading.Lock()
        good: List[str] = []

        def worker_chunk(chunk: List[Tuple[str, int]]):
            for host, port in chunk:
                if self.should_stop():
                    return
                self.wait_if_paused()
                ok = self.try_connect(host, port)
                if ok:
                    ipport = f"{host}:{port}"
                    self.bus.good_ip.emit(ipport)
                    self._save_realtime(ipport)
                    with lock:
                        good.append(ipport)
                with lock:
                    self.done += 1
                    self.bus.progress.emit(int(self.done * 100 / self.total))

        tasks: List[Tuple[str, int]] = []
        for ip in self.ips:
            for p in self.cfg.ports:
                tasks.append((ip, p))

        n = max(1, self.cfg.threads)
        chunks = [tasks[i::n] for i in range(n)]
        threads: List[threading.Thread] = []
        for ch in chunks:
            t = threading.Thread(target=worker_chunk, args=(ch,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        if good or self._saved_set:
            all_set = set(good).union(self._saved_set)
            with open(self.cfg.realtime_path, "w", encoding="utf-8") as f:
                for line in sorted(all_set):
                    f.write(line + "\n")
            self.bus.log.emit(f"Saved {self.cfg.realtime_path} with {len(all_set)} entries")
            self.bus.status.emit(f"{self.cfg.realtime_path} saved")
        self.bus.finished.emit("Port scan finished")


# ------------------------------ Proxy ------------------------------

class ProxyWorker(CancellableWorker):
    def __init__(self, bus: Bus, proxies: List[str], timeout_ms: int):
        super().__init__()
        self.bus = bus
        self.proxies = proxies
        self.timeout_ms = timeout_ms
        self.total = max(1, len(self.proxies))
        self.done = 0

    def run(self):
        good = []
        for p in self.proxies:
            if self.should_stop():
                break
            self.wait_if_paused()
            host, port = (p.split(":", 1) + [""])[:2]
            ok = False
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout_ms / 1000.0)
                s.connect((host, int(port)))
                ok = True
            except Exception:
                ok = False
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            if ok:
                good.append(p)
            self.done += 1
            self.bus.progress.emit(int(self.done * 100 / self.total))
        if good:
            with open("Good_Proxy.txt", "w", encoding="utf-8") as f:
                for g in sorted(set(good)):
                    f.write(g + "\n")
            self.bus.log.emit(f"Saved Good_Proxy.txt with {len(set(good))} entries")
            self.bus.status.emit("Good_Proxy.txt saved")
        self.bus.finished.emit("Proxy check finished")


class TabProxy(QWidget):
    def __init__(self, bus: Bus, app_settings: GlobalSettings):
        super().__init__()
        self.bus = bus
        self.app_settings = app_settings
        self.pool = QThreadPool.globalInstance()
        self.worker: Optional[ProxyWorker] = None

        self.bus.finished.connect(self.on_any_finished)

        outer = QVBoxLayout(self)
        box = QGroupBox("Proxy Manager")
        layout = QVBoxLayout(box)

        self.text = QTextEdit(); self.text.setPlaceholderText("Paste proxies host:port, one per line")
        row = QHBoxLayout()
        row.addWidget(QLabel("Timeout(ms):"))
        self.spin_timeout = QSpinBox(); self.spin_timeout.setRange(100, 10000); self.spin_timeout.setValue(self.app_settings.timeout_ms)
        row.addWidget(self.spin_timeout)
        self.btn_start = QPushButton("Start")
        self.btn_pause = QPushButton("Pause")
        self.btn_resume = QPushButton("Resume")
        self.btn_stop = QPushButton("Stop")
        self.progress = QProgressBar(); self.progress.setRange(0, 100); self.progress.setFormat("%p%")
        row.addWidget(self.btn_start); row.addWidget(self.btn_pause); row.addWidget(self.btn_resume); row.addWidget(self.btn_stop); row.addWidget(self.progress)

        layout.addWidget(self.text)
        layout.addLayout(row)
        outer.addWidget(box)

        self.btn_start.clicked.connect(self.start)
        self.btn_pause.clicked.connect(self.pause)
        self.btn_resume.clicked.connect(self.resume)
        self.btn_stop.clicked.connect(self.stop)

        bus.progress.connect(self.progress.setValue)
        bus.apply_settings.connect(self.refresh_from_settings)

        self._set_btn_states(running=False, paused=False)

    def _colorize(self, btn: QPushButton, bg: str, fg: str = "white"):
        btn.setStyleSheet("QPushButton { background: %s; color: %s; padding:6px 12px; border-radius:6px; }"
                          "QPushButton:disabled { background: #555; color: #bbb; }"
                          "QPushButton:hover { background: #505054; }" % (bg, fg))

    def _set_btn_states(self, running: bool, paused: bool):
        self.btn_start.setEnabled(not running)
        self.btn_pause.setEnabled(running and not paused)
        self.btn_resume.setEnabled(running and paused)
        self.btn_stop.setEnabled(running)
        if not running:
            self._colorize(self.btn_start, "#2e7d32")
            self._colorize(self.btn_pause, "#777")
            self._colorize(self.btn_resume, "#777")
            self._colorize(self.btn_stop, "#777")
        else:
            self._colorize(self.btn_start, "#444")
            self._colorize(self.btn_stop, "#c62828")
            if paused:
                self._colorize(self.btn_pause, "#444")
                self._colorize(self.btn_resume, "#1565c0")
            else:
                self._colorize(self.btn_pause, "#ef6c00")
                self._colorize(self.btn_resume, "#444")

    @Slot()
    def refresh_from_settings(self):
        self.spin_timeout.setValue(self.app_settings.timeout_ms)

    def start(self):
        if self.worker:
            QMessageBox.information(self, "Busy", "Task already running")
            return
        proxies = [l.strip() for l in self.text.toPlainText().splitlines() if l.strip()]  
        if not proxies:
            QMessageBox.warning(self, "No proxies", "Paste proxies first.")
            return
        self.worker = ProxyWorker(self.bus, proxies, self.app_settings.timeout_ms)
        QThreadPool.globalInstance().start(self.worker)
        self._set_btn_states(running=True, paused=False)
        self.bus.log.emit("Proxy test started")
        self.bus.status.emit("Proxy test started")

    def pause(self):
        if self.worker:
            self.worker.pause(); self._set_btn_states(running=True, paused=True)
            self.bus.log.emit("Proxy test paused"); self.bus.status.emit("Paused")

    def resume(self):
        if self.worker:
            self.worker.resume(); self._set_btn_states(running=True, paused=False)
            self.bus.log.emit("Proxy test resumed"); self.bus.status.emit("Resumed")

    def stop(self):
        if self.worker:
            self.worker.stop(); self.worker = None; self._set_btn_states(running=False, paused=False)
            self.bus.log.emit("Proxy test stopped"); self.bus.status.emit("Stopped")

    @Slot(str)
    def on_any_finished(self, msg: str):
        if "Proxy check finished" in msg:
            self.worker = None
            self._set_btn_states(running=False, paused=False)
            self.progress.setValue(100)
            self.bus.status.emit("Proxy check finished")


# ------------------------------ Validate ------------------------------

@dataclass
class ValidateSettings:
    threads: int = 50
    timeout_ms: int = 1500
    use_proxy: bool = False
    realtime_save: bool = True
    realtime_path: str = "Weak_RDP_Creds.csv"
    success_full_save: bool = True
    success_full_csv_path: str = "Success_Full.csv"
    success_full_xlsx: bool = False
    success_full_xlsx_path: str = "Success_Full.xlsx"
    engines: List[str] = field(default_factory=lambda: ["PyRDP+FreeRDP"])
    use_all: bool = False


class ValidationWorker(CancellableWorker):
    def __init__(self, bus: Bus, ips_ports: List[str], creds: List[Tuple[str, str]], settings: ValidateSettings):
        super().__init__()
        self.bus = bus
        self.targets = ips_ports
        self.creds = creds
        self.settings = settings
        engines_count = len(ENGINE_NAMES) if self.settings.use_all else max(1, len(self.settings.engines))
        self.total = max(1, len(self.targets) * max(1, len(self.creds)) * engines_count)
        self.done = 0
        self._csv_file = None
        self._writer = None
        self._succ_csv_file = None
        self._succ_writer = None
        if self.settings.realtime_save:
            self._prepare_csv()
        if self.settings.success_full_save:
            self._prepare_success_csv()

    def _prepare_csv(self):
        header_needed = (not os.path.exists(self.settings.realtime_path)) or (os.path.getsize(self.settings.realtime_path) == 0)
        self._csv_file = open(self.settings.realtime_path, "a", newline="", encoding="utf-8")
        self._writer = csv.writer(self._csv_file)
        if header_needed:
            self._writer.writerow(["ip_port", "username", "credential_id", "cred_hash", "result", "engine", "method", "timestamp"])
            self._csv_file.flush()

    def _prepare_success_csv(self):
        header_needed = (not os.path.exists(self.settings.success_full_csv_path)) or (os.path.getsize(self.settings.success_full_csv_path) == 0)
        self._succ_csv_file = open(self.settings.success_full_csv_path, "a", newline="", encoding="utf-8")
        self._succ_writer = csv.writer(self._succ_csv_file)
        if header_needed:
            self._succ_writer.writerow(["IP:Port","Username","Password","Cred ID","Cred Hash","Result","Engine","Method","Timestamp"])
            self._succ_csv_file.flush()

    def _write_row(self, row: List[str]):
        if self._writer is None:
            return
        self._writer.writerow(row)
        self._csv_file.flush()

    def _write_success_csv(self, row_full: List[str]):
        if self._succ_writer is None:
            return
        self._succ_writer.writerow(row_full)
        self._succ_csv_file.flush()

    def _write_success_xlsx(self, row_full: List[str]):
        if not self.settings.success_full_xlsx:
            return
        try:
            from openpyxl import Workbook, load_workbook
        except Exception:
            self.bus.log.emit("openpyxl not installed; skipping .xlsx success save")
            self.settings.success_full_xlsx = False
            return
        path = self.settings.success_full_xlsx_path
        try:
            if os.path.exists(path):
                wb = load_workbook(path)
                ws = wb.active
            else:
                wb = Workbook()
                ws = wb.active
                ws.append(["IP:Port","Username","Password","Cred ID","Cred Hash","Result","Engine","Method","Timestamp"])
            ws.append(row_full)
            wb.save(path)
        except Exception as e:
            self.bus.log.emit(f"Failed to write Excel: {e}")

    def precheck_tcp(self, ip: str, port: int) -> bool:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.settings.timeout_ms / 1000.0)
        try:
            s.connect((ip, port))
            return True
        except Exception:
            return False
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _find_wfreerdp(self) -> Optional[List[str]]:
        for exe in ["wfreerdp.exe", "wfreerdp"]:
            p = shutil.which(exe)
            if p:
                return [p]
        candidates = [
            r"C:\Program Files\FreeRDP\wfreerdp.exe",
            r"C:\Program Files\FreeRDP-nightly\wfreerdp.exe",
            r"C:\Program Files (x86)\FreeRDP\wfreerdp.exe",
        ]
        for p in candidates:
            if os.path.exists(p):
                return [p]
        return None

    def _port_is_free(self, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                return True
            except OSError:
                return False

    def _docker_available(self) -> bool:
        try:
            r = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def _docker_run_pyrdp(self, ip: str, port: int, host_port: int) -> Optional[subprocess.Popen]:
        try:
            cwd = os.getcwd()
            out_dir = os.path.join(cwd, "pyrdp_output")
            os.makedirs(out_dir, exist_ok=True)
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{out_dir}:/home/pyrdp/pyrdp_output",
                "-p", f"{host_port}:3389",
                "gosecure/pyrdp", "pyrdp-mitm", f"{ip}:{port}"
            ]
            self.bus.log.emit(f"Docker: {' '.join(cmd)}")
            return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except Exception as e:
            self.bus.log.emit(f"Docker run failed: {e}")
            return None

    def _start_pyrdp_native(self, ip: str, port: int) -> Optional[subprocess.Popen]:
        try:
            cmd = ["pyrdp-mitm", f"{ip}:{port}"]
            self.bus.log.emit(f"Starting PyRDP MITM: {' '.join(cmd)}")
            return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except Exception as e:
            self.bus.log.emit(f"Failed to start pyrdp-mitm natively: {e}")
            return None

    def _wait_port_ready(self, host: str, port: int, timeout_s: int = 12) -> bool:
        t0 = time.time()
        while time.time() - t0 < timeout_s and not self.should_stop():
            try:
                with socket.create_connection((host, port), timeout=0.5):
                    return True
            except Exception:
                time.sleep(0.2)
        return False

    def validate_with_engine(self, engine: str, ip: str, port: int, username: str, password: str) -> Tuple[bool, str]:
        if engine == "PyRDP+FreeRDP":
            return self.validate_credential_real(ip, port, username, password, force_direct=False)
        elif engine == "FreeRDP (direct)":
            return self.validate_credential_real(ip, port, username, password, force_direct=True)
        elif engine == "Impacket":
            return self.validate_impacket_stub(ip, port, username, password)
        elif engine == "RDPY3":
            return self.validate_rdpy3_stub(ip, port, username, password)
        elif engine == "MsRdpClient":
            return self.validate_msrpclient_stub(ip, port, username, password)
        else:
            return (False, f"Unknown engine: {engine}")

    def validate_credential_real(self, ip: str, port: int, username: str, password: str, force_direct: bool = False) -> Tuple[bool, str]:
        if not self.precheck_tcp(ip, port):
            return (False, "NoTCP")

        freerdp = self._find_wfreerdp()
        if not freerdp:
            self.bus.log.emit("wfreerdp.exe not found in PATH or common locations; please install FreeRDP for Windows.")
            return (False, "NoClient")

        out_replays = Path.cwd() / "pyrdp_output" / "replays"
        before = set(p.name for p in out_replays.glob("*.pyrdp")) if out_replays.exists() else set()

        mitm_proc = None
        connect_host = None
        connect_port = None
        method = "RDP/FreeRDP (direct)"

        if not force_direct:
            if self._port_is_free(3389):
                mitm_proc = self._start_pyrdp_native(ip, port)
                if mitm_proc and self._wait_port_ready("127.0.0.1", 3389, timeout_s=12):
                    connect_host, connect_port = "127.0.0.1", 3389
                    method = "RDP/PyRDP MITM + FreeRDP"

            if connect_host is None and self._docker_available():
                mitm_proc = self._docker_run_pyrdp(ip, port, host_port=3390)
                if mitm_proc and self._wait_port_ready("127.0.0.1", 3390, timeout_s=14):
                    connect_host, connect_port = "127.0.0.1", 3390
                    method = "RDP/PyRDP MITM (Docker) + FreeRDP"
                elif mitm_proc:
                    try:
                        mitm_proc.terminate()
                    except Exception:
                        pass
                    mitm_proc = None

        if connect_host is None:
            connect_host, connect_port = ip, port
            if force_direct:
                method = "RDP/FreeRDP (direct)"

        cmd = freerdp + [f"/v:{connect_host}:{connect_port}", f"/u:{username}", f"/p:{password}", "/cert:ignore", "/dynamic-resolution"]
        timeout_s = max(10, int(self.settings.timeout_ms / 1000) + 15)
        self.bus.log.emit(f"Running FreeRDP: {' '.join(cmd)} (timeout {timeout_s}s)")
        try:
            rc = subprocess.run(cmd, timeout=timeout_s).returncode
        except subprocess.TimeoutExpired:
            rc = 124

        if connect_host == "127.0.0.1":
            time.sleep(1.2)

        after = set(p.name for p in out_replays.glob("*.pyrdp")) if out_replays.exists() else set()
        new_replays = after - before
        success = bool(new_replays) or (rc == 0)

        if mitm_proc:
            try:
                mitm_proc.terminate()
            except Exception:
                pass

        return (success, method)

    def validate_impacket_stub(self, ip: str, port: int, username: str, password: str) -> Tuple[bool, str]:
        if not self.precheck_tcp(ip, port):
            return (False, "NoTCP")
        self.bus.log.emit("Impacket engine is in stub mode.")
        return (False, "Impacket (stub)")

    def validate_rdpy3_stub(self, ip: str, port: int, username: str, password: str) -> Tuple[bool, str]:
        if not self.precheck_tcp(ip, port):
            return (False, "NoTCP")
        self.bus.log.emit("RDPY3 engine is in stub mode.")
        return (False, "RDPY3 (stub)")

    def validate_msrpclient_stub(self, ip: str, port: int, username: str, password: str) -> Tuple[bool, str]:
        if not self.precheck_tcp(ip, port):
            return (False, "NoTCP")
        self.bus.log.emit("MsRdpClient engine is in stub mode.")
        return (False, "MsRdpClient (stub)")

    def run(self):
        try:
            ipports: List[Tuple[str, int]] = []
            for t in self.targets:
                try:
                    host, p = t.split(":", 1)
                    ipports.append((host, int(p)))
                except Exception:
                    continue

            engines_to_use = ENGINE_NAMES if self.settings.use_all else list(self.settings.engines)

            for idx, (username, password) in enumerate(self.creds, start=1):
                label = f"CRED-{idx}"
                cred_hash = log_hash(label, username, password)

                for (ip, port) in ipports:
                    if self.should_stop():
                        break
                    self.wait_if_paused()
                    time.sleep(min(0.05, self.settings.timeout_ms / 1000.0 / 10))

                    for engine in engines_to_use:
                        if self.should_stop():
                            break
                        ok, method = self.validate_with_engine(engine, ip, port, username, password)
                        result_text = "Success" if ok else "Fail"
                        pass_view = password if ok else "******"

                        row_full = [
                            f"{ip}:{port}", username, pass_view, label, cred_hash, result_text, engine, method,
                            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                        ]
                        self.bus.table_row.emit(row_full)

                        if self.settings.realtime_save:
                            csv_row = [f"{ip}:{port}", username, label, cred_hash, result_text, engine, method,
                                       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())]
                            self._write_row(csv_row)

                        if ok and self.settings.success_full_save:
                            row_success = [f"{ip}:{port}", username, password, label, cred_hash, result_text, engine, method,
                                           time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())]
                            self._write_success_csv(row_success)

                        self.done += 1
                        self.bus.progress.emit(int(self.done * 100 / self.total))
        finally:
            try:
                if self._csv_file:
                    self._csv_file.close()
                if self._succ_csv_file:
                    self._succ_csv_file.close()
            except Exception:
                pass
            self.bus.finished.emit("Validation finished")


class TabValidate(QWidget):
    def __init__(self, bus: Bus, app_settings: GlobalSettings):
        super().__init__()
        self.bus = bus
        self.app_settings = app_settings
        self.pool = QThreadPool.globalInstance()
        self.worker: Optional[ValidationWorker] = None
        self.creds: List[Tuple[str, str]] = []  # manual entries
        self.cred_map: Dict[str, Tuple[str, str]] = {}  # CRED-x -> (u,p)
        self.file_users: List[str] = []
        self.file_passwords: List[str] = []

        self.bus.finished.connect(self.on_any_finished)

        outer = QVBoxLayout(self)

        meta_box = QGroupBox("Credentials & Targets")
        meta_layout = QVBoxLayout(meta_box)

        file_row = QHBoxLayout()
        self.txt_ipfile = QLineEdit(); self.txt_ipfile.setPlaceholderText("Good_IPS.txt (default) or Good_IP.txt")
        self.btn_browse_ipfile = QPushButton("Browse...")
        file_row.addWidget(QLabel("IP:Port file:"))
        file_row.addWidget(self.txt_ipfile)
        file_row.addWidget(self.btn_browse_ipfile)

        engine_row = QHBoxLayout()
        self.cmb_engine = QComboBox()
        self.cmb_engine.addItems(ENGINE_NAMES)
        self.chk_use_all_engines = QCheckBox("Use ALL Engines")
        self.chk_use_all_engines.toggled.connect(self.on_use_all_engines_toggled)
        engine_row.addWidget(QLabel("Engine:"))
        engine_row.addWidget(self.cmb_engine)
        engine_row.addStretch(1)
        engine_row.addWidget(self.chk_use_all_engines)

        self.lbl_engine_status = QLabel("")
        meta_layout.addLayout(file_row)
        meta_layout.addLayout(engine_row)
        meta_layout.addWidget(self.lbl_engine_status)

        cred_row = QHBoxLayout()
        self.txt_user = QLineEdit(); self.txt_user.setPlaceholderText("username")
        self.txt_pass = QLineEdit(); self.txt_pass.setPlaceholderText("password"); self.txt_pass.setEchoMode(QLineEdit.Password)
        self.btn_add_cred = QPushButton("Add Credential")
        cred_row.addWidget(self.txt_user); cred_row.addWidget(self.txt_pass); cred_row.addWidget(self.btn_add_cred)

        files_row = QHBoxLayout()
        self.txt_userfile = QLineEdit(); self.txt_userfile.setPlaceholderText("(optional) users.txt")
        self.btn_userfile = QPushButton("Browse Users…")
        self.txt_passfile = QLineEdit(); self.txt_passfile.setPlaceholderText("(optional) passwords.txt")
        self.btn_passfile = QPushButton("Browse Passwords…")
        files_row.addWidget(QLabel("User file:")); files_row.addWidget(self.txt_userfile); files_row.addWidget(self.btn_userfile)
        files_row.addWidget(QLabel("Password file:")); files_row.addWidget(self.txt_passfile); files_row.addWidget(self.btn_passfile)

        meta_layout.addLayout(cred_row)
        meta_layout.addLayout(files_row)

        self.list_creds = QListWidget(); self.list_creds.setAlternatingRowColors(True)

        ctrl = QHBoxLayout()
        self.chk_use_proxy = QCheckBox("Use proxies from Good_Proxy.txt (global toggle applies)")
        self.chk_realtime_validate = QCheckBox("Save Realtime Validate → Weak_RDP_Creds.csv")
        self.chk_realtime_validate.setChecked(True)
        self.chk_success_full = QCheckBox("Save Realtime Success (FULL) → Success_Full.csv")
        self.chk_success_full.setChecked(True)
        self.chk_success_xlsx = QCheckBox("Also write Excel .xlsx (needs openpyxl)")
        self.chk_success_xlsx.setChecked(False)

        ctrl.addWidget(self.chk_use_proxy)
        ctrl.addWidget(self.chk_realtime_validate)
        ctrl.addWidget(self.chk_success_full)
        ctrl.addWidget(self.chk_success_xlsx)

        runrow = QHBoxLayout()
        self.btn_start = QPushButton("Start")
        self.btn_pause = QPushButton("Pause")
        self.btn_resume = QPushButton("Resume")
        self.btn_stop = QPushButton("Stop")
        self.progress = QProgressBar(); self.progress.setRange(0, 100); self.progress.setFormat("%p%")
        runrow.addWidget(self.btn_start); runrow.addWidget(self.btn_pause); runrow.addWidget(self.btn_resume); runrow.addWidget(self.btn_stop); runrow.addWidget(self.progress)

        result_box = QGroupBox("Results")
        result_layout = QVBoxLayout(result_box)
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(["IP:Port","Username","Password","Cred ID","Cred Hash","Result","Engine","Method","Timestamp"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(False)

        filter_row = QHBoxLayout()
        self.cmb_filter_result = QComboBox(); self.cmb_filter_result.addItems(["All", "Success", "Fail"])
        self.cmb_filter_engine = QComboBox(); self.cmb_filter_engine.addItems(["All"] + ENGINE_NAMES)
        self.txt_filter_search = QLineEdit(); self.txt_filter_search.setPlaceholderText("Search IP/Username...")
        btn_clear_filters = QPushButton("Clear")

        filter_row.addWidget(QLabel("Result:")); filter_row.addWidget(self.cmb_filter_result)
        filter_row.addWidget(QLabel("Engine:")); filter_row.addWidget(self.cmb_filter_engine)
        filter_row.addWidget(self.txt_filter_search)
        filter_row.addWidget(btn_clear_filters)

        result_layout.addLayout(filter_row)

        self.btn_reveal = QPushButton("Reveal selected credential (Success rows only) – and save to disk")

        outer.addWidget(meta_box)
        outer.addWidget(QLabel("Credentials in memory (not saved to disk):"))
        outer.addWidget(self.list_creds)
        outer.addLayout(ctrl)
        outer.addLayout(runrow)
        result_layout.addWidget(self.table)
        result_layout.addWidget(self.btn_reveal)
        outer.addWidget(result_box)

        self.btn_browse_ipfile.clicked.connect(self.browse_ipfile)
        self.btn_userfile.clicked.connect(self.browse_userfile)
        self.btn_passfile.clicked.connect(self.browse_passfile)
        self.btn_add_cred.clicked.connect(self.add_cred)
        self.btn_start.clicked.connect(self.start)
        self.btn_pause.clicked.connect(self.pause)
        self.btn_resume.clicked.connect(self.resume)
        self.btn_stop.clicked.connect(self.stop)
        self.btn_reveal.clicked.connect(self.reveal_selected)

        self.cmb_filter_result.currentIndexChanged.connect(self.apply_filters)
        self.cmb_filter_engine.currentIndexChanged.connect(self.apply_filters)
        self.txt_filter_search.textChanged.connect(self.apply_filters)
        btn_clear_filters.clicked.connect(self._clear_filters)

        self.bus.table_row.connect(self.add_result_row)
        self.bus.progress.connect(self.progress.setValue)

        self._sort_orders = {}
        self.table.horizontalHeader().sectionClicked.connect(self.on_header_clicked)

        self._set_btn_states(running=False, paused=False)
        self.update_engine_status()
        self.on_use_all_engines_toggled(self.chk_use_all_engines.isChecked())

    def _colorize(self, btn: QPushButton, bg: str, fg: str = "white"):
        btn.setStyleSheet(f"QPushButton {{ background: {bg}; color: {fg}; padding:6px 12px; border-radius:6px; }}"
                          f"QPushButton:disabled {{ background: #555; color: #bbb; }}"
                          f"QPushButton:hover {{ background: #505054; }}")

    def _set_btn_states(self, running: bool, paused: bool):
        self.btn_start.setEnabled(not running)
        self.btn_pause.setEnabled(running and not paused)
        self.btn_resume.setEnabled(running and paused)
        self.btn_stop.setEnabled(running)
        if not running:
            self._colorize(self.btn_start, "#2e7d32")
            self._colorize(self.btn_pause, "#777")
            self._colorize(self.btn_resume, "#777")
            self._colorize(self.btn_stop, "#777")
        else:
            self._colorize(self.btn_start, "#444")
            if paused:
                self._colorize(self.btn_pause, "#444")
                self._colorize(self.btn_resume, "#1565c0")
            else:
                self._colorize(self.btn_pause, "#ef6c00")
                self._colorize(self.btn_resume, "#444")
            self._colorize(self.btn_stop, "#c62828")

    def _clear_filters(self):
        self.cmb_filter_result.setCurrentIndex(0)
        self.cmb_filter_engine.setCurrentIndex(0)
        self.txt_filter_search.clear()

    def browse_ipfile(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select IP:Port file", ".", "Text Files (*.txt);;All Files (*)")
        if path:
            self.txt_ipfile.setText(path)

    def browse_userfile(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select users file", ".", "Text Files (*.txt);;All Files (*)")
        if path:
            self.txt_userfile.setText(path)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.file_users = [l.strip() for l in f if l.strip()]
                self.bus.log.emit(f"Loaded {len(self.file_users)} users from {path}")
            except Exception as e:
                QMessageBox.warning(self, "Read error", f"Could not read users file: {e}")

    def browse_passfile(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select passwords file", ".", "Text Files (*.txt);;All Files (*)")
        if path:
            self.txt_passfile.setText(path)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.file_passwords = [l.strip() for l in f if l.strip()]
                self.bus.log.emit(f"Loaded {len(self.file_passwords)} passwords from {path}")
            except Exception as e:
                QMessageBox.warning(self, "Read error", f"Could not read passwords file: {e}")

    def add_cred(self):
        u = self.txt_user.text().strip(); p = self.txt_pass.text()
        if not u or not p:
            QMessageBox.warning(self, "Missing", "Enter username and password")
            return
        self.creds.append((u, p))
        label = f"CRED-{len(self.creds)}"
        self.cred_map[label] = (u, p)
        self.list_creds.addItem(QListWidgetItem(f"{label}  →  {u} / ******"))
        self.txt_user.clear(); self.txt_pass.clear()

    def load_good_ips(self) -> List[str]:
        candidates: List[str] = []
        p = self.txt_ipfile.text().strip()
        if p:
            candidates.append(p)
        candidates.extend(["Good_IPS.txt", "Good_IP.txt"])
        for path in candidates:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        self.bus.log.emit(f"Loaded targets from {path}")
                        return [l.strip() for l in f if l.strip()]
                except Exception as e:
                    QMessageBox.warning(self, "Read error", f"Could not read {path}: {e}")
                    return []
        QMessageBox.warning(self, "Missing", "Provide an IP:Port file (Good_IPS.txt or Good_IP.txt)")
        return []

    def build_credential_list(self) -> List[Tuple[str, str]]:
        pairs = list(self.creds)
        for u in self.file_users:
            for p in self.file_passwords:
                pairs.append((u, p))
        seen = set()
        uniq = []
        for u, p in pairs:
            key = (u, p)
            if key in seen:
                continue
            seen.add(key)
            uniq.append((u, p))
        cap = self.app_settings.max_creds  # 0 means unlimited
        if cap and len(uniq) > cap:
            self.bus.log.emit(f"Safety cap: trimming credentials from {len(uniq)} to {cap}")
            uniq = uniq[:cap]
        self.cred_map.clear()
        self.list_creds.clear()
        for i, (u, p) in enumerate(uniq, start=1):
            self.cred_map[f"CRED-{i}"] = (u, p)
            self.list_creds.addItem(QListWidgetItem(f"CRED-{i}  →  {u} / ******"))
        return uniq

    def start(self):
        if self.worker:
            QMessageBox.information(self, "Busy", "Validation already running")
            return
        targets = self.load_good_ips()
        if not targets:
            return
        creds = self.build_credential_list()
        if not creds:
            QMessageBox.warning(self, "No creds", "Provide at least one credential (manual or via files)")
            return

        selected_engine = self.cmb_engine.currentText()
        engines = [selected_engine]
        use_all = self.chk_use_all_engines.isChecked()

        vs = ValidateSettings(
            threads=self.app_settings.threads,
            timeout_ms=self.app_settings.timeout_ms,
            use_proxy=self.app_settings.use_proxy or self.chk_use_proxy.isChecked(),
            realtime_save=self.chk_realtime_validate.isChecked(),
            realtime_path="Weak_RDP_Creds.csv",
            success_full_save=self.chk_success_full.isChecked(),
            success_full_csv_path="Success_Full.csv",
            success_full_xlsx=self.chk_success_xlsx.isChecked(),
            success_full_xlsx_path="Success_Full.xlsx",
            engines=engines,
            use_all=use_all
        )

        self.worker = ValidationWorker(self.bus, targets, creds, vs)
        QThreadPool.globalInstance().start(self.worker)
        self._set_btn_states(running=True, paused=False)
        mode = "ALL engines" if use_all else f"engine={selected_engine}"
        self.bus.log.emit(f"Validation started ({mode})")
        self.bus.status.emit("Validation started")

    def pause(self):
        if self.worker:
            self.worker.pause(); self._set_btn_states(running=True, paused=True)
            self.bus.log.emit("Validation paused"); self.bus.status.emit("Paused")

    def resume(self):
        if self.worker:
            self.worker.resume(); self._set_btn_states(running=True, paused=False)
            self.bus.log.emit("Validation resumed"); self.bus.status.emit("Resumed")

    def stop(self):
        if self.worker:
            self.worker.stop(); self.worker = None; self._set_btn_states(running=False, paused=False)
            self.bus.log.emit("Validation stopped"); self.bus.status.emit("Stopped")

    @Slot(list)
    def add_result_row(self, row: List[str]):
        r = self.table.rowCount()
        self.table.insertRow(r)
        for c, val in enumerate(row):
            item = QTableWidgetItem(val)
            if c == 5 and val == "Success":
                item.setForeground(QColor("#4caf50"))
            elif c == 5 and val == "Fail":
                item.setForeground(QColor("#e53935"))
            self.table.setItem(r, c, item)
        self.apply_filters()

    def apply_filters(self):
        want_result = self.cmb_filter_result.currentText()
        want_engine = self.cmb_filter_engine.currentText()
        q = self.txt_filter_search.text().strip().lower()

        rows = self.table.rowCount()
        for r in range(rows):
            ip = self.table.item(r, 0).text() if self.table.item(r, 0) else ""
            user = self.table.item(r, 1).text() if self.table.item(r, 1) else ""
            result = self.table.item(r, 5).text() if self.table.item(r, 5) else ""
            engine = self.table.item(r, 6).text() if self.table.item(r, 6) else ""

            ok_result = (want_result == "All") or (result == want_result)
            ok_engine = (want_engine == "All") or (engine == want_engine)
            ok_search = (q == "") or (q in ip.lower() or q in user.lower())

            self.table.setRowHidden(r, not (ok_result and ok_engine and ok_search))

    @Slot(bool)
    def on_use_all_engines_toggled(self, checked: bool):
        self.cmb_engine.setEnabled(not checked)

    @Slot(int)
    def on_header_clicked(self, col: int):
        order = getattr(self, "_sort_orders", {}).get(col, Qt.AscendingOrder)
        order = Qt.DescendingOrder if order == Qt.AscendingOrder else Qt.AscendingOrder
        self._sort_orders[col] = order
        self._manual_sort(col, order)

    def _manual_sort(self, col: int, order):
        rows = self.table.rowCount()
        cols = self.table.columnCount()
        data = []
        for r in range(rows):
            row_items = [self.table.item(r, c) for c in range(cols)]
            values = [row_items[c].text() if row_items[c] else "" for c in range(cols)]
            data.append(values)

        def key_func(values):
            v = values[col]
            if col == 5:  # Result
                rank = 0 if v == "Success" else 1
                return (rank, v.lower())
            elif col == 0:  # IP:Port logical
                try:
                    ip, port = v.split(":")
                    octs = [int(x) for x in ip.split(".")]
                    while len(octs) < 4: octs.append(-1)
                    return (*octs[:4], int(port))
                except Exception:
                    return (999,999,999,999,999999)
            else:
                return v.lower()

        data.sort(key=key_func, reverse=(order == Qt.DescendingOrder))

        self.table.setRowCount(0)
        for values in data:
            r = self.table.rowCount()
            self.table.insertRow(r)
            for c, val in enumerate(values):
                item = QTableWidgetItem(val)
                if c == 5 and val == "Success":
                    item.setForeground(QColor("#4caf50"))
                elif c == 5 and val == "Fail":
                    item.setForeground(QColor("#e53935"))
                self.table.setItem(r, c, item)

    def reveal_selected(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Select", "Select a result row first")
            return
        result = self.table.item(row, 5).text() if self.table.item(row, 5) else ""
        if result != "Success":
            QMessageBox.information(self, "Only Success", "Reveal is allowed only for Success rows")
            return
        cred_id = self.table.item(row, 3).text() if self.table.item(row, 3) else ""
        if cred_id not in self.cred_map:
            QMessageBox.warning(self, "Not in memory", "Credential mapping not found (session only)")
            return
        ip_port = self.table.item(row, 0).text() if self.table.item(row, 0) else ""
        u, p = self.cred_map[cred_id]

        QMessageBox.information(self, "Credential", f"{cred_id}:\nUsername: {u}\nPassword: {p}")

        try:
            with open("Good_RDP.txt", "a", encoding="utf-8") as f:
                f.write(f"{ip_port}@{u};{p}\n")
            header_needed = not os.path.exists("Revealed_Creds.csv")
            with open("Revealed_Creds.csv", "a", newline="", encoding="utf-8") as cf:
                writer = csv.writer(cf)
                if header_needed:
                    writer.writerow(["ip_port","username","password","timestamp"])
                writer.writerow([ip_port, u, p, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())])
            self.bus.log.emit("Saved to Good_RDP.txt and Revealed_Creds.csv")
            self.bus.status.emit("Credentials saved to disk")
        except Exception as e:
            QMessageBox.warning(self, "Save error", f"Could not save revealed credential: {e}")

    def update_engine_status(self):
        states = detect_engines()
        lines = [f"{k}: {v}" for k, v in states.items()]
        self.lbl_engine_status.setText(" • ".join(lines))

    @Slot(str)
    def on_any_finished(self, msg: str):
        if "Validation finished" in msg:
            self.worker = None
            self._set_btn_states(running=False, paused=False)
            self.progress.setValue(100)
            self.bus.status.emit("Validation finished")


# ------------------------------ Targets & Scan ------------------------------

class TabTargets(QWidget):
    def __init__(self, bus: Bus, app_settings: GlobalSettings):
        super().__init__()
        self.bus = bus
        self.app_settings = app_settings
        self.pool = QThreadPool.globalInstance()
        self.worker: Optional[PortScanWorker] = None

        self.bus.finished.connect(self.on_any_finished)

        outer = QVBoxLayout(self)

        ip_box = QGroupBox("Targets (CIDR / Range)")
        ip_layout = QVBoxLayout(ip_box)
        self.input = QTextEdit()
        self.input.setPlaceholderText(
            "Paste CIDR or IP ranges here, one per line.\n"
            "Examples:\n"
            "  192.168.1.0/24\n"
            "  10.0.0.5-10.0.0.100\n"
            "  203.0.113.10"
        )
        row_top = QHBoxLayout()
        self.btn_load_ipfile = QPushButton("Load ip_ranges.txt")
        self.btn_save_ipfile = QPushButton("Save as ip_ranges.txt")
        self.lbl_count = QLabel("0 IPs expanded")
        row_top.addWidget(self.btn_load_ipfile)
        row_top.addWidget(self.btn_save_ipfile)
        row_top.addStretch(1)
        row_top.addWidget(self.lbl_count)
        ip_layout.addWidget(self.input)
        ip_layout.addLayout(row_top)

        scan_box = QGroupBox("Port Scan")
        scan_layout = QVBoxLayout(scan_box)
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Ports (comma):"))
        self.txt_ports = QLineEdit("3389,3388,3399,3390,3391,3392")
        row1.addWidget(self.txt_ports)
        row1.addWidget(QLabel("Timeout(ms):"))
        self.spin_timeout = QSpinBox(); self.spin_timeout.setRange(100, 10000); self.spin_timeout.setValue(self.app_settings.timeout_ms)
        row1.addWidget(self.spin_timeout)
        row1.addWidget(QLabel("Threads:"))
        self.spin_threads = QSpinBox(); self.spin_threads.setRange(1, 2000); self.spin_threads.setValue(self.app_settings.threads)
        row1.addWidget(self.spin_threads)

        row2 = QHBoxLayout()
        self.btn_start = QPushButton("Start")
        self.btn_pause = QPushButton("Pause")
        self.btn_resume = QPushButton("Resume")
        self.btn_stop = QPushButton("Stop")
        self.progress = QProgressBar(); self.progress.setRange(0, 100); self.progress.setFormat("%p%")
        row2.addWidget(self.btn_start); row2.addWidget(self.btn_pause); row2.addWidget(self.btn_resume); row2.addWidget(self.btn_stop); row2.addWidget(self.progress)

        row3 = QHBoxLayout()
        self.chk_realtime_scan = QCheckBox("Save Realtime Port Scan → Good_IPS.txt")
        self.chk_realtime_scan.setChecked(True)
        row3.addWidget(self.chk_realtime_scan)
        row3.addStretch(1)

        self.list_good = QListWidget(); self.list_good.setAlternatingRowColors(True)
        scan_layout.addLayout(row1)
        scan_layout.addLayout(row2)
        scan_layout.addLayout(row3)
        scan_layout.addWidget(QLabel("Open RDP endpoints (IP:Port):"))
        scan_layout.addWidget(self.list_good)

        outer.addWidget(ip_box)
        outer.addWidget(scan_box)

        self.input.textChanged.connect(self.on_text_changed)
        self.btn_load_ipfile.clicked.connect(self.load_ip_ranges)
        self.btn_save_ipfile.clicked.connect(self.save_ip_ranges)
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_pause.clicked.connect(self.pause_scan)
        self.btn_resume.clicked.connect(self.resume_scan)
        self.btn_stop.clicked.connect(self.stop_scan)

        bus.progress.connect(self.progress.setValue)
        bus.good_ip.connect(self.on_good_ip)
        bus.apply_settings.connect(self.refresh_from_settings)

        self._set_btn_states(running=False, paused=False)

    def _colorize(self, btn: QPushButton, bg: str, fg: str = "white"):
        btn.setStyleSheet(f"QPushButton {{ background: {bg}; color: {fg}; padding:6px 12px; border-radius:6px; }}"
                          f"QPushButton:disabled {{ background: #555; color: #bbb; }}"
                          f"QPushButton:hover {{ background: #505054; }}")

    def _set_btn_states(self, running: bool, paused: bool):
        self.btn_start.setEnabled(not running)
        self.btn_pause.setEnabled(running and not paused)
        self.btn_resume.setEnabled(running and paused)
        self.btn_stop.setEnabled(running)
        if not running:
            self._colorize(self.btn_start, "#2e7d32")
            self._colorize(self.btn_pause, "#777")
            self._colorize(self.btn_resume, "#777")
            self._colorize(self.btn_stop, "#777")
        else:
            self._colorize(self.btn_start, "#444")
            if paused:
                self._colorize(self.btn_pause, "#444")
                self._colorize(self.btn_resume, "#1565c0")
            else:
                self._colorize(self.btn_pause, "#ef6c00")
                self._colorize(self.btn_resume, "#444")
            self._colorize(self.btn_stop, "#c62828")

    @Slot()
    def refresh_from_settings(self):
        self.spin_timeout.setValue(self.app_settings.timeout_ms)
        self.spin_threads.setValue(self.app_settings.threads)

    def expand_all(self) -> List[str]:
        tokens = [line.strip() for line in self.input.toPlainText().splitlines() if line.strip()]
        seen: Set[str] = set()
        out: List[str] = []
        for t in tokens:
            for ip in expand_ip_token(t):
                if ip not in seen:
                    seen.add(ip)
                    out.append(ip)
        return out

    def on_text_changed(self):
        self.lbl_count.setText(f"{len(self.expand_all())} IPs expanded")

    def load_ip_ranges(self):
        try:
            with open("ip_ranges.txt", "r", encoding="utf-8") as f:
                self.input.setText(f.read())
                self.bus.log.emit("Loaded ip_ranges.txt")
                self.bus.status.emit("ip_ranges.txt loaded")
        except FileNotFoundError:
            QMessageBox.warning(self, "Missing", "ip_ranges.txt not found in current folder.")

    def save_ip_ranges(self):
        with open("ip_ranges.txt", "w", encoding="utf-8") as f:
            f.write(self.input.toPlainText())
        self.bus.log.emit("Saved ip_ranges.txt")
        self.bus.status.emit("ip_ranges.txt saved")

    def parse_ports(self) -> List[int]:
        out = []
        for p in self.txt_ports.text().split(','):
            p = p.strip()
            if not p:
                continue
            try:
                val = int(p)
                if 1 <= val <= 65535:
                    out.append(val)
            except Exception:
                pass
        return out or [3389]

    def start_scan(self):
        if self.worker:
            QMessageBox.information(self, "Busy", "A scan is already running.")
            return
        ips = self.expand_all()
        if not ips:
            QMessageBox.warning(self, "No IPs", "No IPs to scan. Fill targets above or load ip_ranges.txt.")
            return
        cfg = ScanConfig(
            ports=self.parse_ports(),
            timeout_ms=self.app_settings.timeout_ms,
            threads=self.app_settings.threads,
            realtime_save=self.chk_realtime_scan.isChecked(),
            realtime_path="Good_IPS.txt",
        )
        self.worker = PortScanWorker(self.bus, ips, cfg)
        self.pool.start(self.worker)
        self._set_btn_states(running=True, paused=False)
        self.bus.log.emit(
            f"Port scan started with {len(ips)} IPs × {len(cfg.ports)} ports; "
            f"threads={cfg.threads}, timeout={cfg.timeout_ms}ms, realtime_save={cfg.realtime_save}"
        )
        self.bus.status.emit("Port scan started")

    def pause_scan(self):
        if self.worker:
            self.worker.pause(); self._set_btn_states(running=True, paused=True)
            self.bus.log.emit("Scan paused"); self.bus.status.emit("Paused")

    def resume_scan(self):
        if self.worker:
            self.worker.resume(); self._set_btn_states(running=True, paused=False)
            self.bus.log.emit("Scan resumed"); self.bus.status.emit("Resumed")

    def stop_scan(self):
        if self.worker:
            self.worker.stop(); self.worker = None; self._set_btn_states(running=False, paused=False)
            self.bus.log.emit("Scan stopped"); self.bus.status.emit("Stopped")

    @Slot(str)
    def on_any_finished(self, msg: str):
        if "Port scan finished" in msg:
            self.worker = None
            self._set_btn_states(running=False, paused=False)
            self.progress.setValue(100)
            self.bus.status.emit("Port scan finished")

    @Slot(str)
    def on_good_ip(self, ipport: str):
        if self.list_good.findItems(ipport, Qt.MatchFixedString):
            return
        self.list_good.addItem(QListWidgetItem(ipport))


# ------------------------------ Engine detection (status) ------------------------------

def detect_engines() -> Dict[str, str]:
    info: Dict[str, str] = {}

    freerdp = None
    for exe in ["wfreerdp.exe", "wfreerdp"]:
        p = shutil.which(exe)
        if p: freerdp = p; break
    if not freerdp:
        for p in [r"C:\Program Files\FreeRDP\wfreerdp.exe",
                  r"C:\Program Files\FreeRDP-nightly\wfreerdp.exe",
                  r"C:\Program Files (x86)\FreeRDP\wfreerdp.exe"]:
            if os.path.exists(p): freerdp = p; break
    info["FreeRDP (direct)"] = "OK" if freerdp else "Missing (install FreeRDP)"

    native = shutil.which("pyrdp-mitm") is not None
    docker_ok = False
    try:
        r = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=5)
        docker_ok = (r.returncode == 0)
    except Exception:
        docker_ok = False
    info["PyRDP+FreeRDP"] = "OK (native)" if native else ("OK (via Docker)" if docker_ok else "Missing (no pyrdp, no Docker)")

    imp = shutil.which("rdp_check.py") or shutil.which("rdp_check")
    info["Impacket"] = "Found rdp_check" if imp else "Missing (rdp_check)"

    try:
        __import__("rdpy")
        info["RDPY3"] = "OK (rdpy module)"
    except Exception:
        info["RDPY3"] = "Missing (pip install rdpy)"

    try:
        import platform
        if platform.system().lower() == "windows":
            try:
                import win32com.client  # type: ignore
                info["MsRdpClient"] = "OK (pywin32 installed)"
            except Exception:
                info["MsRdpClient"] = "Missing (pywin32)"
        else:
            info["MsRdpClient"] = "Windows-only"
    except Exception:
        info["MsRdpClient"] = "Unknown"
    return info


# ------------------------------ Settings tab ------------------------------

class TabSettings(QWidget):
    def __init__(self, bus: Bus, app_settings: GlobalSettings):
        super().__init__()
        self.bus = bus
        self.app_settings = app_settings
        outer = QVBoxLayout(self)

        box = QGroupBox("Global Settings")
        form = QFormLayout(box)
        self.spin_threads = QSpinBox(); self.spin_threads.setRange(1, 2000); self.spin_threads.setValue(self.app_settings.threads)
        self.spin_timeout = QSpinBox(); self.spin_timeout.setRange(100, 10000); self.spin_timeout.setValue(self.app_settings.timeout_ms)
        self.chk_proxy = QCheckBox("Use Proxy (global)"); self.chk_proxy.setChecked(self.app_settings.use_proxy)
        self.spin_maxcreds = QSpinBox(); self.spin_maxcreds.setRange(0, 1000000); self.spin_maxcreds.setSpecialValueText("No limit")
        self.spin_maxcreds.setToolTip("0 = No limit. Use with care to avoid account lockouts.")
        self.spin_maxcreds.setValue(self.app_settings.max_creds)
        form.addRow("Threads:", self.spin_threads)
        form.addRow("Timeout (ms):", self.spin_timeout)
        form.addRow("Use Proxy:", self.chk_proxy)
        form.addRow("Max Cred Combos:", self.spin_maxcreds)

        log_box = QGroupBox("Live Log")
        v = QVBoxLayout(log_box)
        self.log = QTextEdit(); self.log.setReadOnly(True)
        v.addWidget(self.log)

        row = QHBoxLayout()
        self.btn_save = QPushButton("Save Settings (apply to all tabs)")
        row.addStretch(1)
        row.addWidget(self.btn_save)

        outer.addWidget(box)
        outer.addLayout(row)
        outer.addWidget(log_box)

        self.btn_save.clicked.connect(self.save_settings)
        self.bus.log.connect(self.append)
        self.bus.finished.connect(self.append)

    @Slot()
    def save_settings(self):
        self.app_settings.threads = self.spin_threads.value()
        self.app_settings.timeout_ms = self.spin_timeout.value()
        self.app_settings.use_proxy = self.chk_proxy.isChecked()
        self.app_settings.max_creds = self.spin_maxcreds.value()
        cap_text = "∞" if self.app_settings.max_creds == 0 else str(self.app_settings.max_creds)
        self.bus.apply_settings.emit()
        self.bus.log.emit(f"Settings saved: threads={self.app_settings.threads}, timeout={self.app_settings.timeout_ms}ms, use_proxy={self.app_settings.use_proxy}, max_creds={cap_text}")
        self.bus.status.emit("Settings applied")

    @Slot(str)
    def append(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.log.append(f"[{ts}] {msg}")


# ------------------------------ Main ------------------------------

class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Safe RDP Access Auditor – Engines (Windows + PyRDP) [SAFE FINAL]")
        self.resize(1240, 840)
        self.bus = Bus()
        self.app_settings = GlobalSettings()

        QApplication.setStyle("Fusion")
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(37, 37, 38))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(30, 30, 30))
        palette.setColor(QPalette.AlternateBase, QColor(45, 45, 48))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(45, 45, 48))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.Highlight, QColor(14, 99, 156))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        self.setPalette(palette)

        self.setStyleSheet("""
            QWidget { font-size: 13px; }
            QGroupBox { border: 1px solid #555; border-radius: 8px; margin-top: 12px; padding: 8px; }
            QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; }
            QPushButton { padding: 6px 12px; border-radius: 6px; }
            QProgressBar { text-align: center; height: 16px; }
            QTableWidget { gridline-color: #555; }
        """)

        tabs = QTabWidget()
        self.tab_targets = TabTargets(self.bus, self.app_settings)
        self.tab_proxy = TabProxy(self.bus, self.app_settings)
        self.tab_validate = TabValidate(self.bus, self.app_settings)
        self.tab_settings = TabSettings(self.bus, self.app_settings)

        tabs.addTab(self.tab_targets, "Targets & Scan")
        tabs.addTab(self.tab_proxy, "Proxy")
        tabs.addTab(self.tab_validate, "Validate (Engines)")
        tabs.addTab(self.tab_settings, "Settings & Log")

        self.setCentralWidget(tabs)

        sb = QStatusBar(); self.setStatusBar(sb)
        self.bus.status.connect(sb.showMessage)


def main():
    app = QApplication(sys.argv)
    w = Main()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
