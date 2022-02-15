from PySide6.QtWidgets import QApplication, QHeaderView
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import Qt, QAbstractTableModel

from interface import *
import sys

class PacketTableModel(QAbstractTableModel):

    cols = ["Index", "Timestamp", "PID", "Length", "Data"]

    pid_names = [
            "RSVD", "OUT", "ACK", "DATA0",
            "PING", "SOF", "NYET", "DATA2",
            "SPLIT", "IN", "NAK", "DATA1",
            "ERR", "SETUP", "STALL", "MDATA"]

    def __init__(self, parent):
        super().__init__(parent)
        if len(sys.argv) < 2:
            self.capture = load_capture()
        else:
            self.capture = convert_capture(sys.argv[1].encode('ascii'))

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
        elif col == 4:
            if packet.pid & PID_TYPE_MASK != DATA:
                return None
            start = packet.data_offset
            end = packet.data_offset + packet.length
            packet_data = self.capture.data[start:end]
            return str.join(" ", ("%02X" % byte for byte in packet_data))

app = QApplication.instance() or QApplication([])
ui = QUiLoader().load('packets.ui')
model = PacketTableModel(app)
ui.tableView.setModel(model)
header = ui.tableView.horizontalHeader()
header.setVisible(True)
header.setSectionResizeMode(QHeaderView.ResizeToContents)
header.setStretchLastSection(True)
ui.tableView.show()
ui.show()
app.exec()
