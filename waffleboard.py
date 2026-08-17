"""
waffleboard - Linux Security Process Monitor
v1.3 - Modern UI inspired by btop

a terminal-based system monitor built with Textual, inspired by
btop / htop / neofetch / bpytop.

this is the v1.x "simple version" milestone: it only displays
live CPU, GPU and RAM usage as animated percentage bars, plus the
detected hardware (CPU model, GPU model, total RAM). security/
process-analysis features are planned for later versions
(see README.md)

layout is a responsive grid of bordered panels that fills the
terminal with modern styling inspired by btop.
"""

from __future__ import annotations

import pathlib
import platform
import shutil
import socket
import subprocess
import time
from collections import deque
from dataclasses import dataclass

import psutil

try:
    from rich.text import Text
except ImportError:
    # Fallback if rich is not available
    class Text:
        def __init__(self, text, style=None):
            self.text = text
            self.style = style
        def __str__(self):
            return self.text

from textual.app import App, ComposeResult
from textual.containers import Grid, Horizontal, Vertical, Container
from textual.coordinate import Coordinate
from textual.reactive import reactive
from textual.timer import Timer
from textual.widgets import DataTable, Header, Input, Label, ProgressBar, Static, Sparkline
from textual.events import Key

REFRESH_TIME = 5.0

def get_cpu_model() -> str:
    """read the CPU model name, linux-specific via /proc/cpuinfo."""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass

    proc = platform.processor() or platform.uname().processor
    return proc or "Unknown CPU"


def get_gpu_model() -> str | None:
    """GPU model name via nvidia-smi, then lspci."""
    exe = shutil.which("nvidia-smi")
    if exe:
        try:
            result = subprocess.run(
                [exe, "--query-gpu=name", "--format=csv,noheader"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().splitlines()[0].strip()
        except Exception:
            pass

    lspci = shutil.which("lspci")
    if lspci:
        try:
            result = subprocess.run([lspci], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    low = line.lower()
                    if "vga compatible controller" in low or "3d controller" in low:
                        parts = line.split(":", 2)
                        if len(parts) >= 3:
                            return parts[2].strip()
        except Exception:
            pass

    return None


@dataclass
class HardwareInfo:
    hostname: str
    os_info: str
    cpu_model: str
    cpu_cores: int
    gpu_model: str | None
    ram_total_gb: float


def hardware_info() -> HardwareInfo:
    return HardwareInfo(
        hostname=socket.gethostname(),
        os_info=f"{platform.system()} {platform.release()}",
        cpu_model=get_cpu_model(),
        cpu_cores=psutil.cpu_count(logical=True) or 1,
        gpu_model=get_gpu_model(),
        ram_total_gb=psutil.virtual_memory().total / (1024 ** 3),
    )


def read_nvidia_smi() -> float | None:
    exe = shutil.which("nvidia-smi")
    if not exe:
        return None
    try:
        result = subprocess.run(
            [exe, "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0 and result.stdout.strip():
            return float(result.stdout.strip().splitlines()[0].strip())
    except Exception:
        return None
    return None


def read_amd_gpu() -> float | None:
    for card in pathlib.Path("/sys/class/drm").glob("card*/device/gpu_busy_percent"):
        try:
            return float(card.read_text().strip())
        except Exception:
            continue
    return None


def get_gpu_usage() -> float | None:
    pct = read_nvidia_smi()
    if pct is not None:
        return pct
    return read_amd_gpu()


def format_uptime(seconds: float) -> str:
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def get_uptime() -> str:
    try:
        return format_uptime(time.time() - psutil.boot_time())
    except Exception:
        return "unknown"


def get_cpu_temp() -> float | None:
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            for key in ("coretemp", "k10temp", "cpu_thermal", "acpitz", "amdgpu", "nct6791"):
                if key in temps:
                    for entry in temps[key]:
                        if entry.current and entry.current > 0:
                            return entry.current
            for entries in temps.values():
                for entry in entries:
                    if entry.current and entry.current > 0:
                        return entry.current
    except Exception:
        pass

    for zone in pathlib.Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            if (zone.parent / "type").exists():
                kind = (zone.parent / "type").read_text().strip().lower()
                if "cpu" in kind or "package" in kind or "core" in kind:
                    value = float(zone.read_text().strip()) / 1000.0
                    if value > 0:
                        return value
        except Exception:
            continue
    return None


def get_gpu_temp() -> float | None:
    exe = shutil.which("nvidia-smi")
    if exe:
        try:
            result = subprocess.run(
                [exe, "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0 and result.stdout.strip():
                return float(result.stdout.strip().splitlines()[0].strip())
        except Exception:
            pass

    for temp_file in pathlib.Path("/sys/class/drm").glob("card*/device/hwmon/hwmon*/temp*_input"):
        try:
            value = float(temp_file.read_text().strip())
            if value > 0:
                return value / 1000.0 if value > 1000 else value
        except Exception:
            continue

    return None


@dataclass
class SystemStats:
    cpu: float
    ram: float
    gpu: float | None
    cpu_temp: float | None
    gpu_temp: float | None
    ram_used_gb: float
    ram_total_gb: float
    uptime: str


def collect_stats() -> SystemStats:
    cpu = psutil.cpu_percent(interval=None)
    vm = psutil.virtual_memory()

    return SystemStats(
        cpu=cpu,
        ram=vm.percent,
        gpu=get_gpu_usage(),
        cpu_temp=get_cpu_temp(),
        gpu_temp=get_gpu_temp(),
        ram_used_gb=vm.used / (1024 ** 3),
        ram_total_gb=vm.total / (1024 ** 3),
        uptime=get_uptime(),
    )


def severity(pct: float) -> str:
    if pct < 50:
        return "sev-ok"
    if pct < 80:
        return "sev-warn"
    return "sev-crit"


def temperature_severity(temp: float) -> str:
    if temp < 50.0:
        return "temp-ok"
    if temp < 70.0:
        return "temp-warm"
    if temp < 85.0:
        return "temp-hot"
    return "temp-critical"


# thresholds are tuned for per-process usage (most processes sit under
# a few percent), unlike the whole-system severity() thresholds above.
PROC_LOW_MAX = 3.0
PROC_MED_MAX = 15.0

PROC_COLORS = {
    "low": "#8be9fd",   # cyan
    "medium": "#ffb86c", # orange
    "high": "#ff5555",   # red
}

PROC_DOTS = {
    "low": "●",
    "medium": "●",
    "high": "●",
}


def process_power_level(value: float) -> str:
    """classify a single process usage value (cpu% or mem%) into low/medium/high."""
    if value < PROC_LOW_MAX:
        return "low"
    if value < PROC_MED_MAX:
        return "medium"
    return "high"


class Panel(Vertical):
    def __init__(self, title: str, subtitle: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self.border_title = title
        if subtitle:
            self.border_subtitle = subtitle


class StatCard(Vertical):
    percent: reactive[float] = reactive(0.0)

    def __init__(self, title: str, subtitle: str = "", show_bar: bool = True, **kwargs) -> None:
        super().__init__(**kwargs)
        self.title_text = title
        self.subtitle = subtitle
        self.show_bar = show_bar

    def compose(self) -> ComposeResult:
        yield Static(self.title_text, classes="stat-label")
        if self.show_bar:
            yield ProgressBar(total=100, show_eta=False, id=f"bar-{self.id}")
        yield Static(self.subtitle, classes="stat-value", id=f"value-{self.id}")
        # Always create the unit widget because update_stat() queries it
        # even when this StatCard has no subtitle (e.g. uptime).
        yield Static("", classes="stat-unit", id=f"unit-{self.id}")

    def update_stat(self, percent: float | None, detail: str = "", severity_class: str | None = None) -> None:
        value_widget = self.query_one(f"#value-{self.id}", Static)
        unit_widget = self.query_one(f"#unit-{self.id}", Static)
        bar = self.query_one(ProgressBar) if self.show_bar else None

        self.remove_class("sev-ok", "sev-warn", "sev-crit", "sev-none", "temp-ok", "temp-warm", "temp-hot", "temp-critical", "temp-none")

        if percent is None:
            if bar is not None:
                bar.update(progress=0)
            value_widget.update("N/A")
            unit_widget.update("")
            self.add_class("temp-none")
            return

        if bar is not None:
            bar.update(progress=percent)

        # Update value and unit based on detail
        if detail:
            value_widget.update(detail)
            unit_widget.update("")
        else:
            value_widget.update(f"{percent:.1f}%")
            unit_widget.update("")

        # Apply temperature coloring if applicable
        if severity_class and severity_class.startswith("temp"):
            # Remove all temp classes first
            self.remove_class("temp-ok", "temp-warm", "temp-hot", "temp-critical", "temp-none")
            # Add the specific temp class to the value widget
            if severity_class == "temp-ok":
                value_widget.add_class("temp-ok")
            elif severity_class == "temp-warm":
                value_widget.add_class("temp-warm")
            elif severity_class == "temp-hot":
                value_widget.add_class("temp-hot")
            elif severity_class == "temp-critical":
                value_widget.add_class("temp-critical")
            elif severity_class == "temp-none":
                value_widget.add_class("temp-none")
        elif severity_class and severity_class.startswith("sev"):
            # For usage severity, color the progress bar
            pass  # The progress bar coloring is handled by CSS


class Wave(Static):
    LEVELS = "▁▂▃▄▅▆▇█▇▆▅▄▃▂▁"

    def __init__(self, history_len: int = 50, **kwargs) -> None:
        super().__init__("", **kwargs)
        self._history: deque[float] = deque([0.0] * history_len, maxlen=history_len)
        self._redraw()

    def push(self, value: float) -> None:
        self._history.append(max(0.0, min(100.0, value)))
        self._redraw()

    def _redraw(self) -> None:
        # Generate enough points to fill the widget width
        chars = []
        amplitude = len(self.LEVELS) - 1
        history_list = list(self._history)

        # Generate points for smooth wave - use more points for better resolution
        for index in range(len(history_list)):
            v = history_list[index]
            phase = (index / len(history_list)) * 2 * 3.141592653589793
            level = int(round((v / 100) * amplitude))
            offset = int(round((0.5 + 0.5 * __import__("math").sin(phase)) * level))
            chars.append(self.LEVELS[min(max(offset, 0), amplitude)])

        self.update(f"[#8be9fd]{''.join(chars)}[/#8be9fd]")


class waffleboardApp(App):
    """waffleboard - linux security process monitor"""

    TITLE = "waffleboard"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [("q", "quit", "Quit")]

    CSS = """
    Screen {
        background: #000000;
        color: #e0e0e0;
    }

    #root-grid {
        layout: grid;
        grid-size: 2 2;
        grid-rows: 1fr 1fr;
        grid-columns: 1fr 1fr;
        grid-gutter: 1 1;
        height: 1fr;
        padding: 0;
    }

    #panel-processes {
        row-span: 2;
    }

    #top-left-row {
        width: 100%;
        height: 100%;
    }
    #bottom-left-row {
        width: 100%;
        height: 100%;
    }

    Panel {
        background: #000000;
        border: solid #2a2a2a;
        padding: 1 2;
        height: 100%;
        overflow: hidden;
        color: #e0e0e0;
        border-title-color: #ffffff;
        border-title-style: bold;
        border-subtitle-color: #b0b0b0;
        margin: 0;
    }

    #panel-system         { border-left: solid #2a2a2a; }
    #panel-network-graph  { border-top: solid #2a2a2a; }
    #panel-processes      { border-left: solid #2a2a2a; border-top: solid #2a2a2a; }
    #panel-network        { border-top: solid #2a2a2a; }
    #panel-storage        { border-top: solid #2a2a2a; }

    /* Tab-specific accent colors */
    #panel-system         { border-left: solid #4a90e2; } /* Blue */
    #panel-network-graph  { border-top: solid #7ed321; } /* Green */
    #panel-processes      { border-left: solid #f5a623; border-top: solid #f5a623; } /* Orange */
    #panel-network        { border-top: solid #d0021b; } /* Red */
    #panel-storage        { border-top: solid #9013fe; } /* Purple */

    .panel-content {
        height: 100%;
        padding: 1;
    }

    Wave {
        height: 100%;
        content-align: center middle;
        color: #4a90e2;
        text-style: bold;
    }

    StatCard {
        border: none;
        padding: 0;
        height: auto;
        margin: 0 0 1 0;
        background: transparent;
    }

    .stat-label {
        text-style: bold;
        color: #b0b0b0;
        text-align: left;
        width: 100%;
        height: 1;
    }

    .stat-value {
        color: #ffffff;
        text-align: left;
        width: 100%;
        height: 1;
        text-style: bold;
    }

    .stat-unit {
        color: #b0b0b0;
        text-align: left;
        width: 100%;
        height: 1;
    }

    StatCard.temp-ok .stat-value { color: #50fa7b; }
    StatCard.temp-warm .stat-value { color: #ffb86c; }
    StatCard.temp-hot .stat-value { color: #ffb86c; }
    StatCard.temp-critical .stat-value { color: #ff5555; }
    StatCard.temp-none .stat-value { color: #b0b0b0; }

    ProgressBar {
        height: 1;
        border: none;
    }
    ProgressBar > .bar--bar {
        background: #4a90e2;
    }
    StatCard.sev-ok    ProgressBar > .bar--bar {
        background: #50fa7b;
    }
    StatCard.sev-warn  ProgressBar > .bar--bar {
        background: #ffb86c;
    }
    StatCard.sev-crit  ProgressBar > .bar--bar {
        background: #ff5555;
    }
    StatCard.sev-none  ProgressBar > .bar--bar {
        background: #2e2e2e;
    }

    /* processes table styling */
    #process-table {
        height: 100%;
        width: 100%;
        background: #000000;
        scrollbar-color: #f5a623 #1a1a2e;
        scrollbar-color-hover: #f5a623 #16213e;
        scrollbar-color-active: #f5a623 #0f3460;
        scrollbar-background: rgba(26, 26, 46, 0.4);
        scrollbar-size-vertical: 1;
    }

    #process-table > .datatable--header {
        background: #1a1a2e;
        color: #e0e0e0;
        text-style: bold;
        border-bottom: solid #2a2a2a;
    }

    #process-table > .datatable--cursor {
        background: #f5a623;
        color: #ffffff;
    }

    #process-table > .datatable--hover {
        background: rgba(26, 26, 46, 0.3);
    }

    #footer-right {
        color: #b0b0b0;
        content-align: right middle;
        width: 100%;
    }

    Header {
        background: transparent;
        color: #e0e0e0;
    }
    Footer { background: transparent; }

    /* bottom bar showing quit hint */
    #bottom-bar {
        height: 1;
        padding: 0 1;
        background: transparent;
        content-align: left middle;
    }

    #quit-hint {
        color: #b0b0b0;
        text-style: bold;
        width: auto;
        padding-right: 2;
    }

    Input {
        background: #0a0a0a;
        color: #ffffff;
        border: round #333333;
        margin: 1 0;
        padding: 0 1;
    }

    Input:focus {
        border: round #8be9fd;
        background: rgba(0, 0, 0, 0.3);
        color: #ffffff;
    }

    /* Animated sparkline for process history */
    .sparkline-container {
        height: 3;
        margin: 0 0 1 0;
    }

    .sparkline {
        height: 100%;
        color: #8be9fd;
    }
    """

    def on_key(self, event: Key) -> None:
        """Ensure 'q' quits even if a widget (like the process table) has focus."""
        if event.key == "q":
            self.exit()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle search input changes."""
        if event.input.id == "process-search":
            self._search_term = event.value.lower()
            # Refresh the process table immediately when search changes
            if self._proc_table_ready:
                try:
                    self.update_process_table()
                except Exception:
                    pass

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._timer: Timer | None = None
        self.hw = hardware_info()
        self._last_net_bytes = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        self._last_net_time = time.time()
        # per-process smoothing state: pid -> recent normalized cpu% deque
        self._proc_history: dict[int, deque[float]] = {}
        # last-seen refresh counter for pruning
        self._proc_last_seen: dict[int, int] = {}
        self._refresh_counter = 0
        self._proc_table_ready = False
        self._search_term = ""

    def update_network_rate(self) -> tuple[float, float]:
        counters = psutil.net_io_counters()
        now = time.time()
        total_bytes = counters.bytes_sent + counters.bytes_recv
        delta = max(0.0, total_bytes - self._last_net_bytes)
        elapsed = max(1e-6, now - self._last_net_time)
        self._last_net_bytes = total_bytes
        self._last_net_time = now
        bytes_per_second = delta / elapsed
        # Map bytes per second to 0..100, using 10 MB/s as 100%.
        mapped = min(100.0, (bytes_per_second / (1024**2)) * 10.0)
        return bytes_per_second, mapped

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Grid(id="root-grid"):
            with Vertical():  # Left column
                with Horizontal(id="top-left-row"):
                    with Panel("system", subtitle=self.hw.hostname, id="panel-system"):
                        with Horizontal():
                            with Vertical():
                                yield StatCard("CPU", subtitle=self.hw.cpu_model, id="cpu")
                                yield StatCard("CPU Temp", subtitle="temperature", id="cpu_temp", show_bar=False)
                                yield StatCard("Uptime", show_bar=False, id="uptime")
                            with Vertical():
                                yield StatCard("GPU", subtitle=self.hw.gpu_model or "no GPU detected", id="gpu")
                                yield StatCard("GPU Temp", subtitle="temperature", id="gpu_temp", show_bar=False)
                                yield StatCard("RAM", subtitle=f"{self.hw.ram_total_gb:.1f} GB total", id="ram")
                    with Panel("network", id="panel-network-graph"):
                        yield Static("", classes="card-detail", id="network-rate")
                        yield Wave(id="network-wave")

                with Horizontal(id="bottom-left-row"):
                    yield Panel("network", id="panel-network")
                    yield Panel("storage", id="panel-storage")

            with Panel("processes", id="panel-processes"):
                yield Input(placeholder="search pid or name...", id="process-search")
                yield DataTable(id="process-table", cursor_type="row", zebra_stripes=True)

        # bottom bar: left shows quit hint, right shows a status field
        with Horizontal(id="bottom-bar"):
            yield Static("q: Quit", id="quit-hint")
            yield Static("", id="footer-right")

    def on_mount(self) -> None:
        self.sub_title = f"{self.hw.hostname} • {self.hw.os_info}"
        psutil.cpu_percent(interval=None)  # prime psutil's sampler

        table = self.query_one("#process-table", DataTable)
        table.add_columns("", "PID", "NAME", "USER", "CPU%", "RAM%")
        table.show_cursor = True
        self._proc_table_ready = True

        self.refresh_stats()
        self._timer = self.set_interval(REFRESH_TIME, self.refresh_stats)

    def refresh_stats(self) -> None:
        stats = collect_stats()

        self.query_one("#cpu", StatCard).update_stat(stats.cpu, f"{self.hw.cpu_cores} cores")
        self.query_one("#gpu", StatCard).update_stat(
            stats.gpu, "" if stats.gpu is not None else "usage unavailable"
        )
        self.query_one("#cpu_temp", StatCard).update_stat(
            stats.cpu_temp,
            f"{stats.cpu_temp:.1f}°C" if stats.cpu_temp is not None else "temperature unavailable",
            temperature_severity(stats.cpu_temp) if stats.cpu_temp is not None else None,
        )
        self.query_one("#gpu_temp", StatCard).update_stat(
            stats.gpu_temp,
            f"{stats.gpu_temp:.1f}°C" if stats.gpu_temp is not None else "temperature unavailable",
            temperature_severity(stats.gpu_temp) if stats.gpu_temp is not None else None,
        )
        self.query_one("#ram", StatCard).update_stat(
            stats.ram, f"{stats.ram_used_gb:.1f} / {self.hw.ram_total_gb:.1f} GB"
        )
        self.query_one("#uptime", StatCard).update_stat(0.0, stats.uptime)

        network_bytes, network_rate = self.update_network_rate()
        self.query_one("#network-rate", Static).update(f"{network_bytes / (1024**2):.2f} MB/s")
        self.query_one("#network-wave", Wave).push(network_rate)
        # Update process list panel
        if self._proc_table_ready:
            try:
                self.update_process_table()
            except Exception:
                # don't let process-list errors break refresh
                pass
        # update footer-right with clock/status
        try:
            self.query_one("#footer-right", Static).update(f"{self.hw.hostname} • {self.hw.os_info}  {time.strftime('%H:%M:%S')}")
        except Exception:
            pass

    def update_process_table(self) -> None:
        """populate the processes panel with every running process, sorted by
        resource usage (heaviest first), each row colour-coded green/yellow/red
        by how much CPU or RAM it's using.
        """
        table = self.query_one("#process-table", DataTable)

        try:
            # advance refresh counter for last-seen tracking
            self._refresh_counter += 1
            # iterate processes with common attributes; some may raise during access
            procs = list(
                psutil.process_iter(attrs=("pid", "name", "username", "cpu_percent", "memory_percent"))
            )
            cpus = psutil.cpu_count(logical=True) or 1

            for p in procs:
                pid = int(p.info.get("pid") or 0)
                try:
                    raw = float(p.cpu_percent(interval=None) or 0.0)
                except Exception:
                    raw = float(p.info.get("cpu_percent") or 0.0) or 0.0
                norm = raw / cpus

                hist = self._proc_history.get(pid)
                if hist is None:
                    hist = deque(maxlen=3)
                    self._proc_history[pid] = hist
                hist.append(norm)
                self._proc_last_seen[pid] = self._refresh_counter

            # prune histories for processes that have disappeared
            to_prune = [pid for pid, last in self._proc_last_seen.items() if (self._refresh_counter - last) > 5]
            for pid in to_prune:
                self._proc_last_seen.pop(pid, None)
                self._proc_history.pop(pid, None)

            # build (pid, avg_cpu, mem, name, user) for every live process
            entries: list[tuple[int, float, float, str, str]] = []
            for p in procs:
                pid = int(p.info.get("pid") or 0)
                hist = self._proc_history.get(pid)
                if not hist:
                    continue
                avg_cpu = sum(hist) / len(hist)
                mem = float(p.info.get("memory_percent") or 0.0)
                name = (p.info.get("name") or "?")[:32]
                user = (p.info.get("username") or "?").split("\\")[-1][:16]
                # Filter by search term if provided
                if self._search_term:
                    search_lower = self._search_term
                    if (search_lower in str(pid).lower()) or (search_lower in name.lower()):
                        entries.append((pid, avg_cpu, mem, name, user))
                else:
                    entries.append((pid, avg_cpu, mem, name, user))

            # heaviest processes (by CPU) float to the top
            entries.sort(key=lambda e: e[1], reverse=True)

            # remember where the user has scrolled to, and which row (if any)
            # is selected, so a refresh doesn't yank the view back to the top
            prev_scroll_y = table.scroll_y
            prev_cursor_row = table.cursor_row

            table.clear()
            for pid, cpu, mem, name, user in entries:
                level = process_power_level(max(cpu, mem))
                color = PROC_COLORS[level]
                # Create colored text for all columns based on process level
                pid_text = Text(str(pid), style=color)
                name_text = Text(name[:32], style=color)
                user_text = Text(user[:16], style=color)
                cpu_cell = Text(f"{cpu:5.1f}", style=PROC_COLORS[process_power_level(cpu)])
                mem_cell = Text(f"{mem:5.1f}", style=PROC_COLORS[process_power_level(mem)])
                table.add_row("", pid_text, name_text, user_text, cpu_cell, mem_cell, key=str(pid))

            # restore scroll / cursor position
            row_count = table.row_count
            if row_count:
                table.cursor_coordinate = Coordinate(
                    row=min(max(prev_cursor_row, 0), row_count - 1), column=0
                )
            # Use call_later to ensure scroll restoration happens after DOM update
            self.set_lambda(lambda: setattr(table, 'scroll_y', prev_scroll_y), 0.01)

        except Exception:
            pass


def run() -> None:
    """entry point used by the `waffleboard` launcher."""
    waffleboardApp().run()


if __name__ == "__main__":
    run()