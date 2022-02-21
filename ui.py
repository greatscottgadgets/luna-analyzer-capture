from PySide6.QtWidgets import QApplication, QHeaderView, QTableView
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import Qt, QCoreApplication, QAbstractTableModel, \
        QAbstractItemModel, QModelIndex

from interface import *
import faulthandler
import sys

faulthandler.enable()

event_names = ["PKT", "TRN", "XFR"]

CAPTURE = len(event_names)

class TableModel(QAbstractTableModel):

    def __init__(self, parent, capture):
        super().__init__(parent)
        self.capture = capture

    def columnCount(self, parent):
        return len(self.cols)

    def headerData(self,section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.cols[section]
        return None


class PacketTableModel(TableModel):

    cols = ["Packet Index", "Timestamp", "Addr", "EP", "PID", "Length", "Data"]

    INDEX, TIMESTAMP, ADDR, EP, PID, LENGTH, DATA = range(7)

    def rowCount(self, parent):
        return self.capture.num_packets

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


class TransactionTableModel(TableModel):

    cols = ["Transaction Index", "Timestamp", "Duration", "Type", "Addr", "EP", "Packet Idx", "Packets", "Result", "Data Bytes", "Data"]

    INDEX, TIMESTAMP, DURATION, TYPE, ADDR, EP, PACKET_IDX, NUM_PACKETS, RESULT, DATA_BYTES, DATA = range(11)

    def rowCount(self, parent):
        return self.capture.num_transactions

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
            if first_packet.pid in (SETUP, IN, OUT):
                return first_packet.fields.token.address

        if col == self.EP:
            if first_packet.pid in (SETUP, IN, OUT):
                return first_packet.fields.token.endpoint

        if col == self.PACKET_IDX:
            return transaction.first_packet_index

        if col == self.NUM_PACKETS:
            return transaction.num_packets

        if col == self.RESULT:
            if not transaction.complete:
                return "ERR"
            else:
                return pid_names[last_packet.pid & 0b1111]

        data_valid = transaction.num_packets > 1 and packets[1].pid & PID_TYPE_MASK == DATA

        if not data_valid:
            return

        data_packet = packets[1]

        if col == self.DATA_BYTES:
            return data_packet.length - 3

        if col == self.DATA:
            start = data_packet.data_offset
            end = start + data_packet.length - 3
            packet_data = self.capture.data[start:end]
            return str.join(" ", ("%02X" % byte for byte in packet_data))


class TransferTableModel(TableModel):

    cols = ["Transfer Index", "Timestamp", "Duration", "Type", "Addr", "EP", "Transactions", "Transaction Indices"]

    INDEX, TIMESTAMP, DURATION, TYPE, ADDR, EP, TRANSACTIONS, INDICES = range(8)

    def rowCount(self, parent):
        return self.capture.num_transfers

    def data(self, index, role):
        if not index.isValid() or role != Qt.DisplayRole:
            return None

        row = index.row()
        col = index.column()

        if col == self.INDEX:
            return row

        entry = self.capture.transfer_index[row]
        endpoint_id = entry.endpoint_id
        transfer_id = entry.transfer_id
        endpoint = self.capture.endpoints[endpoint_id]
        endpoint_traffic = self.capture.endpoint_traffic[endpoint_id]
        transfer = endpoint_traffic.transfers[transfer_id]
        endpoint_transaction_ids = endpoint_traffic.transaction_ids
        first_id = transfer.id_offset
        last_id = first_id + transfer.num_transactions - 1
        first_transaction = self.capture.transactions[endpoint_transaction_ids[first_id]]
        last_transaction = self.capture.transactions[endpoint_transaction_ids[last_id]]
        first_packet_index = first_transaction.first_packet_index
        last_packet_index = last_transaction.first_packet_index + last_transaction.num_packets - 1
        first_packet = self.capture.packets[first_packet_index]
        last_packet = self.capture.packets[last_packet_index]

        if col == self.TIMESTAMP:
            offset_ns = first_packet.timestamp_ns - self.capture.packets[0].timestamp_ns
            return "%.9f" % (offset_ns / 1e9)

        if col == self.DURATION:
            return last_packet.timestamp_ns - first_packet.timestamp_ns

        if col == self.TYPE:
            if first_packet.pid == SETUP:
                return "CONTROL"
            elif first_packet.pid == IN:
                return "BULK IN"
            elif first_packet.pid == OUT:
                return "BULK OUT"

        if col == self.ADDR:
            return endpoint.address

        if col == self.EP:
            return endpoint.endpoint

        if col == self.TRANSACTIONS:
            return transfer.num_transactions

        if col == self.INDICES:
            start = first_id
            end = min(last_id + 1, start + 100)
            return str.join(", ", (str(endpoint_transaction_ids[i]) for i in range(start, end)))


class EventTableModel(TableModel):

    cols = ["Event Index", "Timestamp", "Type", "Type Index", "Subtype"]

    INDEX, TIMESTAMP, TYPE, TYPE_INDEX, SUBTYPE = range(5)

    def rowCount(self, parent):
        return self.capture.num_events

    def data(self, index, role):
        if not index.isValid() or role != Qt.DisplayRole:
            return None

        row = index.row()
        col = index.column()

        if col == self.INDEX:
            return row

        event = self.capture.events[row]

        if col == self.TYPE_INDEX:
            return event.index

        if col == self.TYPE:
            return event_names[event.type]

        if event.type == PACKET:
            packet = self.capture.packets[event.index]
        elif event.type == TRANSACTION:
            transaction = self.capture.transactions[event.index]
            packet_id = transaction.first_packet_index
            packet = self.capture.packets[packet_id]
        elif event.type == TRANSFER:
            entry = self.capture.transfer_index[event.index]
            traffic = self.capture.endpoint_traffic[entry.endpoint_id]
            transfer = traffic.transfers[entry.transfer_id]
            transaction_id = traffic.transaction_ids[transfer.id_offset]
            transaction = self.capture.transactions[transaction_id]
            packet_id = transaction.first_packet_index
            packet = self.capture.packets[packet_id]

        if col == self.TIMESTAMP:
            offset_ns = packet.timestamp_ns - self.capture.packets[0].timestamp_ns
            return "%.9f" % (offset_ns / 1e9)

        if col == self.SUBTYPE:
            if event.type in (PACKET, TRANSACTION):
                return pid_names[packet.pid & 0b1111]
            elif event.type == TRANSFER:
                if packet.pid == SETUP:
                    return "CONTROL"
                elif packet.pid == IN:
                    return "BULK IN"
                elif packet.pid == OUT:
                    return "BULK OUT"


class EventTreeItem(object):

    cols = ["Event"]

    def __init__(self, capture, item_type,
            parent_item=None, parent_row=None, item_id=None):
        self.capture = capture
        self.item_type = item_type
        self.parent_item = parent_item
        self.parent_row = parent_row
        self.item_id = item_id
        self.child_cache = {}

    def child(self, row):
        if row in self.child_cache:
            return self.child_cache[row]
        if self.item_type == CAPTURE:
            event = self.capture.events[row]
            child = EventTreeItem(self.capture, event.type, self, row, event.index)
        elif self.item_type == TRANSFER:
            entry = self.capture.transfer_index[self.item_id]
            traffic = self.capture.endpoint_traffic[entry.endpoint_id]
            transfer = traffic.transfers[entry.transfer_id]
            transaction_id = traffic.transaction_ids[transfer.id_offset + row]
            child = EventTreeItem(self.capture, TRANSACTION, self, row, transaction_id)
        elif self.item_type == TRANSACTION:
            transaction = self.capture.transactions[self.item_id]
            packet_id = transaction.first_packet_index + row
            child = EventTreeItem(self.capture, PACKET, self, row, packet_id)
        self.child_cache[row] = child
        return child

    def child_count(self):
        if self.item_type == CAPTURE:
            return self.capture.num_events
        if self.item_type == TRANSFER:
            entry = self.capture.transfer_index[self.item_id]
            traffic = self.capture.endpoint_traffic[entry.endpoint_id]
            transfer = traffic.transfers[entry.transfer_id]
            return transfer.num_transactions
        if self.item_type == TRANSACTION:
            transaction = self.capture.transactions[self.item_id]
            return transaction.num_packets
        if self.item_type == PACKET:
            return 0

    def data(self, col):
        if col != 0:
            return None

        if self.item_type == TRANSFER:
            entry = self.capture.transfer_index[self.item_id]
            ep = self.capture.endpoints[entry.endpoint_id]
            traffic = self.capture.endpoint_traffic[entry.endpoint_id]
            transfer = traffic.transfers[entry.transfer_id]
            transaction_id = traffic.transaction_ids[transfer.id_offset]
            transaction = self.capture.transactions[transaction_id]
            packet_id = transaction.first_packet_index
            packet = self.capture.packets[packet_id]
            if packet.pid == SETUP:
                fmt = "Control transfer on %u.%u with %u transactions"
            elif packet.pid == IN:
                fmt = "Bulk transfer from %u.%u to host with %u transactions"
            elif packet.pid == OUT:
                fmt = "Bulk transfer from host to %u.%u with %u trasactions"
            return fmt % (ep.address, ep.endpoint, transfer.num_transactions)

        if self.item_type == TRANSACTION:
            transaction = self.capture.transactions[self.item_id]
            packet_id = transaction.first_packet_index
            packet = self.capture.packets[packet_id]
            if packet.pid == SOF:
                return "Idle period with %u SOF packets" % transaction.num_packets
            name = pid_names[packet.pid & 0b1111]
            return "%s transaction, %u packets" % (name, transaction.num_packets)

        if self.item_type == PACKET:
            packet = self.capture.packets[self.item_id]
            name = pid_names[packet.pid & 0b1111]
            return "%s packet, %u bytes" % (name, packet.length)


class EventTreeModel(QAbstractItemModel):

    def __init__(self, parent, capture):
        super().__init__(parent)
        self.capture = capture
        self.root_item = EventTreeItem(self.capture, CAPTURE)

    def item(self, index):
        if not index.isValid():
            return self.root_item
        else:
            return index.internalPointer()

    def rowCount(self, parent):
        if parent.column() > 0:
            return 0
        return self.item(parent).child_count()

    def columnCount(self, parent):
        return len(EventTreeItem.cols)

    def headerData(self,section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return EventTreeItem.cols[section]
        return None

    def flags(self, index):
        if not index.isValid():
            return Qt.NoItemFlags
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable

    def index(self, row, column, parent):
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        child_item = self.item(parent).child(row)
        if child_item:
            return self.createIndex(row, column, child_item)
        else:
            return QModelIndex()

    def parent(self, index):
        item = self.item(index)
        if self.root_item in (item, item.parent_item):
            return QModelIndex()
        if item.parent_item.parent_item:
            parent_index = item.parent_item.parent_row
        else:
            parent_index = 0
        return self.createIndex(parent_index, 0, item.parent_item)

    def data(self, index, role):
        if role == Qt.DisplayRole:
            return self.item(index).data(index.column())


capture = convert_capture(sys.argv[1].encode('ascii'))
QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
app = QApplication.instance() or QApplication([])
ui = QUiLoader().load('analyzer.ui')
for modelClass, view in (
        (PacketTableModel, ui.packetView),
        (TransactionTableModel, ui.transactionView),
        (TransferTableModel, ui.transferView),
        (EventTableModel, ui.eventView),
        (EventTreeModel, ui.eventTreeView)):
    model = modelClass(app, capture)
    view.setModel(model)
    if isinstance(view, QTableView):
        header = view.horizontalHeader()
        header.setVisible(True)
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setStretchLastSection(True)
    view.show()
ui.show()
app.exec()
