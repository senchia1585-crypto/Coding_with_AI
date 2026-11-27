
"""
NetMonitor - 本地网络带宽/流量实时监控工具
============================================
用途：监控自己电脑/网络的实时流量，滚动显示抓到的数据包，
      并统计带宽使用、协议分布、各主机流量排行。

依赖：
    pip install scapy rich

运行（需要管理员/root权限，因为要读取网卡原始流量）：
    Windows : 以管理员身份打开终端 -> python net_monitor.py
    macOS   : sudo python3 net_monitor.py
    Linux   : sudo python3 net_monitor.py

按 Ctrl+C 退出。
"""

import sys
import time
import argparse
import threading
from collections import deque, defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, conf, get_if_list
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
except ImportError:
    print("❌ 缺少依赖，请先安装：pip install scapy")
    sys.exit(1)

try:
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.console import Console
    from rich.progress_bar import ProgressBar
    from rich.text import Text
    from rich.align import Align
except ImportError:
    print("❌ 缺少依赖，请先安装：pip install rich")
    sys.exit(1)


# ----------------------------- 全局统计状态 -----------------------------

class Stats:
    def __init__(self, max_rows=18):
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.total_packets = 0
        self.total_bytes = 0
        self.proto_count = defaultdict(int)       # 协议 -> 包数
        self.proto_bytes = defaultdict(int)       # 协议 -> 字节数
        self.host_bytes = defaultdict(int)         # IP -> 字节数（用于排行）
        self.recent_packets = deque(maxlen=max_rows)  # 最近N条包，滚动显示

        # 用于计算实时速率（每秒字节数）
        self.bytes_window = deque(maxlen=10)  # 最近10秒每秒字节数
        self._second_bucket = 0
        self._bucket_start = time.time()

        self.max_seen_bps = 1  # 防止除零，用于进度条比例

    def add_packet(self, proto, length, src, dst, info):
        with self.lock:
            self.total_packets += 1
            self.total_bytes += length
            self.proto_count[proto] += 1
            self.proto_bytes[proto] += length
            self.host_bytes[src] += length

            now = time.time()
            self._second_bucket += length
            if now - self._bucket_start >= 1.0:
                self.bytes_window.append(self._second_bucket)
                self.max_seen_bps = max(self.max_seen_bps, self._second_bucket)
                self._second_bucket = 0
                self._bucket_start = now

            ts = datetime.now().strftime("%H:%M:%S")
            self.recent_packets.append({
                "time": ts,
                "proto": proto,
                "src": src,
                "dst": dst,
                "len": length,
                "info": info,
            })

    def current_bps(self):
        with self.lock:
            if not self.bytes_window:
                return 0
            return self.bytes_window[-1]

    def avg_bps(self):
        with self.lock:
            if not self.bytes_window:
                return 0
            return sum(self.bytes_window) / len(self.bytes_window)


stats = Stats()


# ----------------------------- 工具函数 -----------------------------

def human_bytes(n):
    """把字节数转成人类可读格式"""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(n) < 1024.0:
            return f"{n:6.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def human_bps(n):
    """把字节/秒 转成 bps/Kbps/Mbps 显示（网络习惯用 bit）"""
    bits = n * 8
    for unit in ["bps", "Kbps", "Mbps", "Gbps"]:
        if abs(bits) < 1000.0:
            return f"{bits:7.1f} {unit}"
        bits /= 1000.0
    return f"{bits:.1f} Tbps"


PROTO_COLOR = {
    "TCP": "cyan",
    "UDP": "yellow",
    "ICMP": "magenta",
    "ARP": "green",
    "DNS": "bright_blue",
    "HTTP": "bright_green",
    "HTTPS": "bright_cyan",
    "OTHER": "white",
}


def classify_packet(pkt):
    """解析包，返回 (协议名, 源IP, 目的IP, 长度, 简要信息)"""
    length = len(pkt)
    src, dst, proto, info = "?", "?", "OTHER", ""

    if pkt.haslayer(IP):
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            if dport == 443 or sport == 443:
                proto = "HTTPS"
            elif dport == 80 or sport == 80:
                proto = "HTTP"
            else:
                proto = "TCP"
            flags = str(tcp.flags)
            info = f"{sport} -> {dport} [{flags}]"
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            if dport == 53 or sport == 53:
                proto = "DNS"
            else:
                proto = "UDP"
            info = f"{sport} -> {dport}"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            info = "echo/reply"
        else:
            proto = "IP"
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        src, dst = ip6.src, ip6.dst
        proto = "IPv6"
    elif pkt.haslayer("ARP"):
        proto = "ARP"
        try:
            arp = pkt["ARP"]
            src, dst = arp.psrc, arp.pdst
            info = "who-has/is-at"
        except Exception:
            pass
    else:
        proto = pkt.lastlayer().name if pkt.lastlayer() else "OTHER"

    return proto, src, dst, length, info


# ----------------------------- 抓包回调 -----------------------------

def on_packet(pkt):
    proto, src, dst, length, info = classify_packet(pkt)
    stats.add_packet(proto, length, src, dst, info)


def sniff_thread(iface, bpf_filter):
    kwargs = {"prn": on_packet, "store": False}
    if iface:
        kwargs["iface"] = iface
    if bpf_filter:
        kwargs["filter"] = bpf_filter
    sniff(**kwargs)


# ----------------------------- 界面渲染 -----------------------------

console = Console()


def render_header(elapsed):
    cur = stats.current_bps()
    avg = stats.avg_bps()
    ratio = min(1.0, cur / max(stats.max_seen_bps, 1))

    bar = ProgressBar(total=100, completed=ratio * 100, width=40)

    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(justify="left", ratio=1)
    grid.add_column(justify="left", ratio=2)
    grid.add_column(justify="left", ratio=1)

    left = Text()
    left.append("⏱  运行时长: ", style="bold")
    left.append(f"{int(elapsed)}s\n")
    left.append("📦 总包数: ", style="bold")
    left.append(f"{stats.total_packets}\n")
    left.append("💾 总流量: ", style="bold")
    left.append(human_bytes(stats.total_bytes))

    mid = Table.grid(padding=(0, 1))
    mid.add_column()
    mid.add_column()
    mid.add_row(Text("实时带宽", style="bold white"), Text(human_bps(cur), style="bold bright_green"))
    mid.add_row(bar, "")
    mid.add_row(Text("10s 平均", style="dim"), Text(human_bps(avg), style="dim"))

    right = Text()
    right.append("🌐 接口: ", style="bold")
    right.append(f"{current_iface or '(自动)'}\n")
    right.append("🔍 过滤器: ", style="bold")
    right.append(f"{current_filter or '(无)'}\n")
    right.append("⌨  退出: ", style="bold")
    right.append("Ctrl+C")

    grid.add_row(left, mid, right)
    return Panel(grid, title="🛰️  NetMonitor · 实时流量监控", border_style="bright_cyan")


def render_proto_table():
    table = Table(title="协议分布", border_style="dim", expand=True)
    table.add_column("协议", style="bold")
    table.add_column("包数", justify="right")
    table.add_column("流量", justify="right")
    table.add_column("占比", justify="left")

    total = max(stats.total_bytes, 1)
    items = sorted(stats.proto_bytes.items(), key=lambda x: -x[1])[:8]
    for proto, b in items:
        pct = b / total
        color = PROTO_COLOR.get(proto, "white")
        bar_width = 12
        filled = int(pct * bar_width)
        bar_str = "█" * filled + "░" * (bar_width - filled)
        table.add_row(
            f"[{color}]{proto}[/{color}]",
            str(stats.proto_count[proto]),
            human_bytes(b).strip(),
            f"[{color}]{bar_str}[/{color}] {pct*100:4.1f}%",
        )
    if not items:
        table.add_row("等待数据...", "-", "-", "-")
    return table


def render_top_hosts():
    table = Table(title="主机流量排行 (Top 6)", border_style="dim", expand=True)
    table.add_column("IP 地址", style="bold")
    table.add_column("流量", justify="right")

    items = sorted(stats.host_bytes.items(), key=lambda x: -x[1])[:6]
    for ip, b in items:
        table.add_row(ip, human_bytes(b).strip())
    if not items:
        table.add_row("等待数据...", "-")
    return table


def render_packet_stream():
    table = Table(title="📡 实时数据包流（最近）", border_style="bright_blue", expand=True)
    table.add_column("时间", style="dim", width=10)
    table.add_column("协议", width=7)
    table.add_column("源地址", style="cyan")
    table.add_column("→", width=1, justify="center")
    table.add_column("目的地址", style="magenta")
    table.add_column("长度", justify="right", width=8)
    table.add_column("详情", style="dim")

    rows = list(stats.recent_packets)[::-1]  # 最新的在最上面
    for p in rows:
        color = PROTO_COLOR.get(p["proto"], "white")
        table.add_row(
            p["time"],
            f"[{color}]{p['proto']}[/{color}]",
            p["src"],
            "→",
            p["dst"],
            f"{p['len']}B",
            p["info"],
        )
    if not rows:
        table.add_row("-", "-", "等待抓包...", "", "", "", "")
    return table


def build_layout(elapsed):
    layout = Layout()
    layout.split_column(
        Layout(render_header(elapsed), size=8, name="header"),
        Layout(name="body"),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(render_packet_stream(), name="stream", ratio=2),
    )
    layout["left"].split_column(
        Layout(render_proto_table(), name="proto"),
        Layout(render_top_hosts(), name="hosts"),
    )
    return layout


# ----------------------------- 主程序 -----------------------------

current_iface = None
current_filter = None


def list_interfaces():
    console.print("\n[bold cyan]可用网络接口：[/bold cyan]")
    for i, name in enumerate(get_if_list()):
        console.print(f"  [{i}] {name}")
    console.print()


def main():
    global current_iface, current_filter

    parser = argparse.ArgumentParser(description="NetMonitor - 本地网络带宽/流量实时监控工具")
    parser.add_argument("-i", "--iface", help="指定网卡接口名（不填则自动选择默认接口）", default=None)
    parser.add_argument("-f", "--filter", help="BPF 过滤表达式，例如 'tcp port 443' 或 'udp'", default=None)
    parser.add_argument("--list", action="store_true", help="列出所有可用网卡接口后退出")
    args = parser.parse_args()

    if args.list:
        list_interfaces()
        sys.exit(0)

    current_iface = args.iface
    current_filter = args.filter

    console.print(Panel.fit(
        "[bold bright_cyan]NetMonitor[/bold bright_cyan] · 本地网络带宽/流量实时监控工具\n"
        "[dim]监控自己网络的带宽与实时数据包流[/dim]",
        border_style="bright_cyan"
    ))

    if current_iface is None:
        console.print("[yellow]提示：未指定接口，将使用 scapy 默认接口。可用 --list 查看所有接口，"
                       "用 -i <接口名> 指定。[/yellow]\n")

    # 启动抓包线程（daemon，主线程退出时自动结束）
    t = threading.Thread(target=sniff_thread, args=(current_iface, current_filter), daemon=True)
    try:
        t.start()
    except PermissionError:
        console.print("[bold red]❌ 权限不足！抓包需要管理员/root权限。[/bold red]")
        console.print("  Windows: 以管理员身份运行终端")
        console.print("  macOS/Linux: 使用 sudo python3 net_monitor.py")
        sys.exit(1)

    start = time.time()
    try:
        with Live(build_layout(0), console=console, refresh_per_second=4, screen=True) as live:
            while True:
                time.sleep(0.25)
                elapsed = time.time() - start
                live.update(build_layout(elapsed))
    except KeyboardInterrupt:
        pass
    finally:
        console.print("\n[bold green]✅ 监控已停止。[/bold green]")
        console.print(f"  总运行时间: {int(time.time() - start)}s")
        console.print(f"  总抓包数: {stats.total_packets}")
        console.print(f"  总流量: {human_bytes(stats.total_bytes).strip()}")


if __name__ == "__main__":
    main()
