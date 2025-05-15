import sys
from PyQt5.QtWidgets import QApplication
from lan_alert_gui import IntrusionAlertSystem

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = IntrusionAlertSystem()
    window.show()
    sys.exit(app.exec_())
