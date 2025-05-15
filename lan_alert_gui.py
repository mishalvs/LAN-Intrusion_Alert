from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton,
    QLabel, QStatusBar, QSplitter, QComboBox, QTabWidget, QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import Qt

from graph_widget import LiveGraphCanvas
from packet_sniffer import PacketSniffer
from device_scanner import scan_devices
from signals import PacketSignal

from pyshark.tshark.tshark import get_tshark_interfaces

class IntrusionAlertSystem(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LAN Intrusion Alert System")
        self.setGeometry(100, 100, 1100, 750)
        self.tabs = QTabWidget()
        self.selected_interface = "Wi-Fi"
        self.packet_signal = PacketSignal()

        self.init_ui()

    def init_ui(self):
        self.packet_tab = QWidget()
        self.device_tab = QWidget()

        self.tabs.addTab(self.packet_tab, "📶 Packets & Alerts")
        self.tabs.addTab(self.device_tab, "🔍 Device Fingerprinting")

        self.init_packet_tab()
        self.init_device_tab()

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Status: Idle | Interface: Wi-Fi")

    def init_packet_tab(self):
        layout = QVBoxLayout()

        # Interface dropdown
        interface_layout = QHBoxLayout()
        interface_label = QLabel("Select Interface:")
        self.interface_dropdown = QComboBox()
        try:
            interfaces = get_tshark_interfaces()
            self.interface_dropdown.addItems(interfaces)
        except Exception:
            self.interface_dropdown.addItem("Wi-Fi")
        self.interface_dropdown.currentTextChanged.connect(self.set_interface)
        interface_layout.addWidget(interface_label)
        interface_layout.addWidget(self.interface_dropdown)

        splitter = QSplitter(Qt.Horizontal)
        self.packet_display = QTextEdit()
        self.packet_display.setReadOnly(True)
        self.alert_display = QTextEdit()
        self.alert_display.setReadOnly(True)
        self.alert_display.setStyleSheet("color: red;")
        splitter.addWidget(self.packet_display)
        splitter.addWidget(self.alert_display)

        # Graph
        self.graph = LiveGraphCanvas(self)

        # Buttons
        self.start_btn = QPushButton("▶ Start")
        self.stop_btn = QPushButton("⏹ Stop")
        self.clear_btn = QPushButton("🧹 Clear Logs")
        self.start_btn.clicked.connect(self.start_sniffing)
        self.stop_btn.clicked.connect(self.stop_sniffing)
        self.clear_btn.clicked.connect(self.clear_logs)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.clear_btn)

        layout.addLayout(interface_layout)
        layout.addWidget(QLabel("📶 Live Packet Feed & Alerts"))
        layout.addWidget(splitter)
        layout.addWidget(QLabel("📈 Live Traffic Graph"))
        layout.addWidget(self.graph)
        layout.addLayout(btn_layout)

        self.packet_tab.setLayout(layout)

        # Connect signals
        self.packet_signal.packet_captured.connect(self.packet_display.append)
        self.packet_signal.alert_raised.connect(self.alert_display.append)

    def init_device_tab(self):
        layout = QVBoxLayout()
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(3)
        self.device_table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Vendor"])
        layout.addWidget(self.device_table)
        refresh_btn = QPushButton("🔄 Refresh Device List")
        refresh_btn.clicked.connect(self.scan_devices)
        layout.addWidget(refresh_btn)
        self.device_tab.setLayout(layout)
        self.scan_devices()

    def scan_devices(self):
        devices = scan_devices()
        self.device_table.setRowCount(len(devices))
        for row, device in enumerate(devices):
            self.device_table.setItem(row, 0, QTableWidgetItem(device['ip']))
            self.device_table.setItem(row, 1, QTableWidgetItem(device['mac']))
            self.device_table.setItem(row, 2, QTableWidgetItem(device['vendor']))

    def set_interface(self, interface):
        self.selected_interface = interface
        self.status.showMessage(f"Status: Idle | Interface: {interface}")

    def start_sniffing(self):
        self.sniffer = PacketSniffer(
            self.selected_interface,
            self.packet_display,
            self.alert_display,
            self.graph,
            self.packet_signal
        )
        self.sniffer.sniffing = True
        self.sniffer.start()
        self.status.showMessage(f"Status: Monitoring | Interface: {self.selected_interface}")

    def stop_sniffing(self):
        if hasattr(self, 'sniffer'):
            self.sniffer.sniffing = False
        self.status.showMessage(f"Status: Stopped | Interface: {self.selected_interface}")

    def clear_logs(self):
        self.packet_display.clear()
        self.alert_display.clear()
