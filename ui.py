from PySide6.QtWidgets import QApplication, QHeaderView
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import Qt, QCoreApplication, QAbstractTableModel

from interface import *
import sys

class PacketTableModel(QAbstractTableModel):

    cols = ["Packet Index", "Timestamp", "Addr", "EP", "PID", "Length", "Data"]

    INDEX, TIMESTAMP, ADDR, EP, PID, LENGTH, DATA = range(7)

    pid_names = [
            "RSVD", "OUT", "ACK", "DATA0",
            "PING", "SOF", "NYET", "DATA2",
            "SPLIT", "IN", "NAK", "DATA1",
            "ERR", "SETUP", "STALL", "MDATA"]

    def __init__(self, parent):
        super().__init__(parent)
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

        if col == self.INDEX:
            return row

        packet = self.capture.packets[row]

        if col == self.TIMESTAMP:
            offset_ns = packet.timestamp_ns - self.capture.packets[0].timestamp_ns
            return "%.9f" % (offset_ns / 1e9)

        if col == self.ADDR:
            if packet.pid in (SETUP, IN, OUT):
                return packet.fields.token.address
            return None

        if col == self.EP:
            if packet.pid in (SETUP, IN, OUT):
                return packet.fields.token.endpoint
            return None

        if col == self.PID:
            return self.pid_names[packet.pid & 0b1111]

        if col == self.LENGTH:
            return packet.length

        if col == self.DATA:
            if packet.pid & PID_TYPE_MASK != DATA:
                return None
            start = packet.data_offset
            end = packet.data_offset + packet.length
            packet_data = self.capture.data[start:end]
            return str.join(" ", ("%02X" % byte for byte in packet_data))

QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
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
