from PyQt5.QtCore import QTimer
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

class LiveGraphCanvas(FigureCanvas):
    def __init__(self, parent=None):
        self.fig = Figure(figsize=(5, 3), dpi=100)
        self.ax = self.fig.add_subplot(111)
        super().__init__(self.fig)
        self.setParent(parent)
        self.x_data = list(range(30))
        self.y_data = [0] * 30
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_graph)
        self.timer.start(1000)
        self.packets_in_last_second = 0

    def count_packet(self):
        self.packets_in_last_second += 1

    def update_graph(self):
        self.y_data.pop(0)
        self.y_data.append(self.packets_in_last_second)
        self.packets_in_last_second = 0
        self.ax.clear()
        self.ax.plot(self.x_data, self.y_data, color='blue')
        self.ax.set_title('Packets per Second')
        self.ax.set_xlabel('Time (s)')
        self.ax.set_ylabel('PPS')
        self.ax.set_ylim(0, max(self.y_data) + 5)
        self.draw()
