from PySide6.QtWidgets import QApplication
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import Qt, QAbstractTableModel

import interface

class PacketTableModel(QAbstractTableModel):

    cols = ["Index", "Timestamp", "PID", "Length"]

    pid_names = [
            "RSVD", "OUT", "ACK", "DATA0",
            "PING", "SOF", "NYET", "DATA2",
            "SPLIT", "IN", "NAK", "DATA1",
            "ERR", "SETUP", "STALL", "MDATA"]

    def __init__(self, parent):
        super().__init__(parent)
        self.capture = interface.load_capture()

    def rowCount(self, parent):
        return self.capture.num_packets

    def columnCount(self, parent):
        return len(self.cols)

    def headerData(self,section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.cols[section]
        return None

    def data(self, index, role):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        row = index.row()
        col = index.column()
        if col == 0:
            return row
        packet = self.capture.packets[row]
        if col == 1:
            return packet.timestamp_ns
        elif col == 2:
            return self.pid_names[packet.pid & 0b1111]
        elif col == 3:
            return packet.length

app = QApplication.instance() or QApplication([])
ui = QUiLoader().load('packets.ui')
model = PacketTableModel(app)
ui.tableView.setModel(model)
ui.tableView.horizontalHeader().setVisible(True)
ui.tableView.show()
ui.show()
app.exec()
