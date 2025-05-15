from PyQt5.QtCore import pyqtSignal, QObject

class PacketSignal(QObject):
    packet_captured = pyqtSignal(str)
    alert_raised = pyqtSignal(str)
