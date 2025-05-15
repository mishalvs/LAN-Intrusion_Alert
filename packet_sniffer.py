import pyshark
import time
import threading
from collections import defaultdict

class PacketSniffer(threading.Thread):  # ✅ Inherit from Thread
    def __init__(self, interface, packet_display, alert_display, graph, packet_signal):
        super().__init__()  # ✅ Initialize the Thread
        self.interface = interface
        self.packet_display = packet_display
        self.alert_display = alert_display
        self.graph = graph
        self.signal = packet_signal  # ✅ Fix attribute name (was: self.packet_signal)
        self.sniffing = False
        self.packet_count = defaultdict(list)
        self.last_display_time = defaultdict(lambda: 0)
        self.last_alert_time = {}

    def run(self):  # ✅ This method will be executed when .start() is called
        import asyncio
        asyncio.set_event_loop(asyncio.new_event_loop())
        try:
            capture = pyshark.LiveCapture(interface=self.interface)
            for packet in capture.sniff_continuously():
                if not self.sniffing:
                    break
                self.process_packet(packet)
        except Exception as e:
            self.signal.alert_raised.emit(f"[ERROR] Failed to capture: {e}")

    def process_packet(self, packet):
        try:
            now = time.time()
            src_ip = packet.ip.src
            if now - self.last_display_time[src_ip] >= 1:
                summary = f"[{packet.sniff_time}] {packet.highest_layer} - {src_ip} → {packet.ip.dst}"
                self.signal.packet_captured.emit(summary)
                self.last_display_time[src_ip] = now
            self.detect_threat(packet, src_ip, now)
            self.graph.count_packet()
        except AttributeError:
            pass

    def detect_threat(self, packet, src_ip, now):
        self.packet_count[src_ip].append(now)
        self.packet_count[src_ip] = [t for t in self.packet_count[src_ip] if now - t < 5]
        if len(self.packet_count[src_ip]) > 20:
            key = f"{src_ip}_flood"
            if self.last_alert_time.get(key, 0) < now - 5:
                self.signal.alert_raised.emit(
                    f"[ALERT] 🚨 Flood from {src_ip} ({len(self.packet_count[src_ip])} packets in 5s)")
                self.last_alert_time[key] = now

        if hasattr(packet, 'tcp'):
            dst_port = packet.tcp.dstport
            if dst_port in ['23', '2323', '3389', '22']:
                key = f"{src_ip}_portscan_{dst_port}"
                if self.last_alert_time.get(key, 0) < now - 5:
                    self.signal.alert_raised.emit(
                        f"[ALERT] 🛑 Suspicious port scan to port {dst_port} from {src_ip}")
                    self.last_alert_time[key] = now
