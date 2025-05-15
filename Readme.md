# 🛡️ LAN Intrusion Alert System

A real-time LAN monitoring and intrusion detection tool built with PyQt5, Scapy, and PyShark. Detects threats, visualizes traffic, and fingerprints connected devices.

---

## 📦 Features

- 🔍 **Live Packet Monitoring** with PyShark
- 🚨 **Threat Detection** (flooding, port scans)
- 📊 **Real-time Traffic Graph** (Packets/sec)
- 🔎 **Device Fingerprinting** using ARP scan
- 🎛️ Intuitive **PyQt5 GUI**

---

## ✅ Requirements

### 🖥️ System Requirements

| Dependency | Purpose | How to Install |
|------------|---------|----------------|
| **Python 3.8–3.11** | Runtime | https://python.org |
| **TShark (from Wireshark)** | Packet capture backend for PyShark | https://www.wireshark.org/download.html (Enable TShark during install) |


---

### 📦 Python Dependencies

Install all dependencies via pip:

```bash
pip install -r requirements.txt
