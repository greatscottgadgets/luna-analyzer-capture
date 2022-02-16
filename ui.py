from PySide6.QtWidgets import QApplication, QHeaderView
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import Qt, QCoreApplication, QAbstractTableModel

from interface import *
import sys

pid_names = [
        "RSVD", "OUT", "ACK", "DATA0",
        "PING", "SOF", "NYET", "DATA2",
        "SPLIT", "IN", "NAK", "DATA1",
        "ERR", "SETUP", "STALL", "MDATA"]

class PacketTableModel(QAbstractTableModel):

    cols = ["Packet Index", "Timestamp", "Addr", "EP", "PID", "Length", "Data"]

    INDEX, TIMESTAMP, ADDR, EP, PID, LENGTH, DATA = range(7)

    def __init__(self, parent, capture):
        super().__init__(parent)
        self.capture = capture

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
            return pid_names[packet.pid & 0b1111]

        if col == self.LENGTH:
            return packet.length

        if col == self.DATA:
            if packet.pid & PID_TYPE_MASK != DATA:
                return None
            start = packet.data_offset
            end = packet.data_offset + packet.length
            packet_data = self.capture.data[start:end]
            return str.join(" ", ("%02X" % byte for byte in packet_data))


class TransactionTableModel(QAbstractTableModel):

    cols = ["Transaction Index", "Timestamp", "Duration", "Type", "Addr", "EP", "Packets", "Result", "Data Bytes", "Data"]

    INDEX, TIMESTAMP, DURATION, TYPE, ADDR, EP, PACKETS, RESULT, DATA_BYTES, DATA = range(10)

    def __init__(self, parent, capture):
        super().__init__(parent)
        self.capture = capture

    def rowCount(self, parent):
        return self.capture.num_transactions

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

        transaction = self.capture.transactions[row]
        start = transaction.first_packet_index
        end = start + transaction.num_packets
        packets = self.capture.packets[start:end]
        first_packet = packets[0]
        last_packet = packets[transaction.num_packets - 1]

        if col == self.TIMESTAMP:
            offset_ns = first_packet.timestamp_ns - self.capture.packets[0].timestamp_ns
            return "%.9f" % (offset_ns / 1e9)

        if col == self.DURATION:
            return last_packet.timestamp_ns - first_packet.timestamp_ns

        if col == self.TYPE:
            return pid_names[first_packet.pid & 0b1111]

        if col == self.ADDR:
            return first_packet.fields.token.address

        if col == self.EP:
            return first_packet.fields.token.endpoint

        if col == self.PACKETS:
            return transaction.num_packets

        if col == self.RESULT:
            if not transaction.complete:
                return "INCOMPLETE"
            else:
                return pid_names[last_packet.pid & 0b1111]

        data_valid = transaction.num_packets > 1 and packets[1].pid & PID_TYPE_MASK == DATA
        data_packet = packets[1]

        if col == self.DATA_BYTES and data_valid:
            return data_packet.length - 3

        if col == self.DATA and data_valid:
            start = data_packet.data_offset
            end = start + data_packet.length - 3
            packet_data = self.capture.data[start:end]
            return str.join(" ", ("%02X" % byte for byte in packet_data))

capture = convert_capture(sys.argv[1].encode('ascii'))
QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
app = QApplication.instance() or QApplication([])
ui = QUiLoader().load('analyzer.ui')
for modelClass, view in (
        (PacketTableModel, ui.packetView),
        (TransactionTableModel, ui.transactionView)):
    model = modelClass(app, capture)
    view.setModel(model)
    header = view.horizontalHeader()
    header.setVisible(True)
    header.setSectionResizeMode(QHeaderView.ResizeToContents)
    header.setStretchLastSection(True)
    view.show()
ui.show()
app.exec()
