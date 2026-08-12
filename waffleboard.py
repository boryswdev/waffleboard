"""
waffleboard - Linux Security Process Monitor
v1.2 - base Monitor (CPU / GPU / RAM)

a terminal-based system monitor built with Textual, inspired by
btop / htop / neofetch / bpytop.

this is the v1.x "simple version" milestone: it only displays
live CPU, GPU and RAM usage as animated percentage bars, plus the
detected hardware (CPU model, GPU model, total RAM). security/
process-analysis features are planned for later versions
(see README.md)

layout is a fixed grid of bordered, btop-style panels that fills the
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

from textual.app import App, ComposeResult
from textual.containers import Grid, Horizontal, Vertical
from textual.reactive import reactive
from textual.timer import Timer
from textual.widgets import Footer, Header, Label, ProgressBar, Static

REFRESH_TIME = 1.0  

def get_cpu_model() -> str:
    """read the CPU model name, ;inux-specific via /proc/cpuinfo."""
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
        cpu = cpu,
        ram = vm.percent,
        gpu = get_gpu_usage(),
        cpu_temp = get_cpu_temp(),
        gpu_temp = get_gpu_temp(),
        ram_used_gb = vm.used / (1024 ** 3),
        ram_total_gb = vm.total / (1024 ** 3),
        uptime = get_uptime(),
    )


def severity(pct: float) -> str:
    if pct < 50:
        return "sev-ok"
    if pct < 80:
        return "sev-warn"
    return "sev-crit"


def temperature_severity(temp: float) -> str:
    if temp < 70.0:
        return "temp-ok"
    if temp < 85.0:
        return "temp-warn"
    return "temp-crit"

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
        yield Label(f"[bold]{self.title_text}[/bold]", classes="card-title", markup=True)
        if self.subtitle:
            yield Static(self.subtitle, classes="card-subtitle")
        if self.show_bar:
            yield ProgressBar(total=100, show_eta=False, id=f"bar-{self.id}")
        yield Static("", classes="card-detail", id=f"detail-{self.id}")

    def update_stat(self, percent: float | None, detail: str = "", severity_class: str | None = None) -> None:
        detail_widget = self.query_one(f"#detail-{self.id}", Static)
        bar = self.query_one(ProgressBar) if self.show_bar else None

        self.remove_class("sev-ok", "sev-warn", "sev-crit", "sev-none", "temp-ok", "temp-warn", "temp-crit", "temp-none")

        if percent is None:
            if bar is not None:
                bar.update(progress=0)
            detail_widget.update("not available")
            self.add_class("temp-none")
            return

        if bar is not None:
            bar.update(progress=percent)

        detail_widget.update(detail)
        self.add_class(severity_class or severity(percent))


class Wave(Static):

    LEVELS = "▁▂▃▄▅▆▇█▇▆▅▄▃▂▁"

    def __init__(self, history_len: int = 24, **kwargs) -> None:
        super().__init__("", **kwargs)
        self._history: deque[float] = deque([0.0] * history_len, maxlen=history_len)
        self._redraw()

    def push(self, value: float) -> None:
        self._history.append(max(0.0, min(100.0, value)))
        self._redraw()

    def _redraw(self) -> None:
        chars = []
        amplitude = len(self.LEVELS) - 1
        for index, v in enumerate(self._history):
            phase = (index / len(self._history)) * 2 * 3.141592653589793
            level = int(round((v / 100) * amplitude))
            offset = int(round((0.5 + 0.5 * __import__("math").sin(phase)) * level))
            chars.append(self.LEVELS[min(max(offset, 0), amplitude)])
        self.update(f"[#bc8cff]{''.join(chars)}[/#bc8cff]")

class waffleboardApp(App):
    """waffleboard - linux security process monitor"""

    TITLE = "waffleboard"
    ENABLE_COMMAND_PALETTE = False

    CSS = """
    Screen {
        background: black;
    }

    #root-grid {
        layout: grid;
        grid-size: 2 2;
        grid-rows: 1fr 1fr;
        grid-columns: 1fr 1fr;
        grid-gutter: 1 1;
        height: 1fr;
        padding: 0 1 1 1;
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
        background: #05060a;
        padding: 0 1;
        height: 100%;
        overflow: hidden;
        color: $text;
    }

    #panel-system        { border: round #2f6b9a; width: 3fr; }
    #panel-network-graph { border: round #6f4db8; width: 1fr; }
    #panel-processes     { border: round #a23b3b; row-span: 2; }
    #panel-network       { border: round #2f8a4e; height: 1fr; }
    #panel-storage   { border: round #b67a1a; height: 1fr; }

    Wave {
        height: auto;
        content-align: center middle;
    }

    StatCard {
        border: none;
        padding: 0;
        height: auto;
        margin: 0 0 1 0;
    }

    .card-title {
        text-style: bold;
        color: $text;
        height: 1;
    }

    .card-subtitle {
        color: $text-muted;
        height: auto;
    }

    .card-detail {
        color: $text-muted;
        height: auto;
    }

    StatCard.temp-ok .card-detail { color: #3fb950; }
    StatCard.temp-warn .card-detail { color: #d29922; }
    StatCard.temp-crit .card-detail { color: #f85149; }
    StatCard.temp-none .card-detail { color: $text-muted; }

    ProgressBar {
        width: 100%;
        height: 1;
    }

    ProgressBar > .bar--bar        { color: #58a6ff; }
    StatCard.sev-ok    ProgressBar > .bar--bar { color: #3fb950; }
    StatCard.sev-warn  ProgressBar > .bar--bar { color: #d29922; }
    StatCard.sev-crit  ProgressBar > .bar--bar { color: #f85149; }
    StatCard.sev-none  ProgressBar > .bar--bar { color: #545862; }

    /* btop-like titles */
    .card-title { text-style: bold; color: $text; }

    Header { background: black; }
    Footer { background: black; }
    """

    BINDINGS = [
        ("q", "quit", "quit"),
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._timer: Timer | None = None
        self.hw = hardware_info()
        self._last_net_bytes = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        self._last_net_time = time.time()

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
            with Horizontal(id="top-left-row"):
                with Panel("system", subtitle = self.hw.hostname, id="panel-system"):
                        with Horizontal():
                            with Vertical():
                                yield StatCard("CPU", subtitle = self.hw.cpu_model, id="cpu")
                                yield StatCard("CPU Temp", subtitle = "temperature", id="cpu_temp", show_bar=False)
                                yield StatCard("Uptime", show_bar=False, id="uptime")
                            with Vertical():
                                yield StatCard("GPU", subtitle = self.hw.gpu_model or "no GPU detected", id="gpu")
                                yield StatCard("GPU Temp", subtitle = "temperature", id="gpu_temp", show_bar=False)
                                yield StatCard("RAM", subtitle = f"{self.hw.ram_total_gb:.1f} GB total", id="ram")
                with Panel("network", id="panel-network-graph"):
                    yield Static("", classes="card-detail", id="network-rate")
                    yield Wave(id="network-wave")

            yield Panel("processes", id="panel-processes")

            with Vertical(id="bottom-left-row"):
                yield Panel("network", id="panel-network")
                yield Panel("storage", id="panel-storage")

        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = f"{self.hw.hostname} • {self.hw.os_info}"
        psutil.cpu_percent(interval=None)  # prime psutil's sampler
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
            stats.ram, f"{stats.ram_used_gb:.1f} / {stats.ram_total_gb:.1f} GB"
        )
        self.query_one("#uptime", StatCard).update_stat(0.0, stats.uptime)

        network_bytes, network_rate = self.update_network_rate()
        self.query_one("#network-rate", Static).update(f"{network_bytes / (1024**2):.2f} MB/s")
        self.query_one("#network-wave", Wave).push(network_rate)


def run() -> None:
    """entry point used by the `waffleboard` launcher."""
    waffleboardApp().run()


if __name__ == "__main__":
    run()