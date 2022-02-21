from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from interface import *

# Base class for table models
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

# Table model for packets
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
                return packet.fields.token.endpoint_num
            return None

        if col == self.PID:
            return pid_names[packet.pid & PID_MASK]

        if col == self.LENGTH:
            return packet.length

        if col == self.DATA:
            if packet.pid & PID_TYPE_MASK != DATA:
                return None
            start = packet.data_offset
            end = packet.data_offset + packet.length
            packet_data = self.capture.data[start:end]
            return str.join(" ", ("%02X" % byte for byte in packet_data))

# Table model for transactions
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
        start = transaction.first_packet_id
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
            return pid_names[first_packet.pid & PID_MASK]

        if col == self.ADDR:
            if first_packet.pid in (SETUP, IN, OUT):
                return first_packet.fields.token.address

        if col == self.EP:
            if first_packet.pid in (SETUP, IN, OUT):
                return first_packet.fields.token.endpoint_num

        if col == self.PACKET_IDX:
            return transaction.first_packet_id

        if col == self.NUM_PACKETS:
            return transaction.num_packets

        if col == self.RESULT:
            if not transaction.complete:
                return "ERR"
            else:
                return pid_names[last_packet.pid & PID_MASK]

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

# Table model for transfers
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
        endpoint = self.capture.endpoints[entry.endpoint_id]
        ep_traffic = self.capture.endpoint_traffic[entry.endpoint_id]
        transfer = ep_traffic.transfers[entry.transfer_id]
        first_id = transfer.ep_tran_offset
        last_id = first_id + transfer.num_transactions - 1
        first_transaction = self.capture.transactions[ep_traffic.transaction_ids[first_id]]
        last_transaction = self.capture.transactions[ep_traffic.transaction_ids[last_id]]
        first_packet_id = first_transaction.first_packet_id
        last_packet_id = last_transaction.first_packet_id + last_transaction.num_packets - 1
        first_packet = self.capture.packets[first_packet_id]
        last_packet = self.capture.packets[last_packet_id]

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
            return endpoint.endpoint_num

        if col == self.TRANSACTIONS:
            return transfer.num_transactions

        if col == self.INDICES:
            start = first_id
            end = min(last_id + 1, start + 100)
            return str.join(", ", (str(ep_traffic.transaction_ids[i]) for i in range(start, end)))

# Table model for events
class EventTableModel(TableModel):

    cols = ["Event Index", "Timestamp", "Type", "Type Index", "Subtype"]

    INDEX, TIMESTAMP, TYPE, TYPE_INDEX, SUBTYPE = range(5)

    event_names = ["PKT", "TRN", "XFR"]

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
            return event.id

        if col == self.TYPE:
            return self.event_names[event.type]

        if event.type == PACKET:
            packet = self.capture.packets[event.id]
        elif event.type == TRANSACTION:
            transaction = self.capture.transactions[event.id]
            packet_id = transaction.first_packet_id
            packet = self.capture.packets[packet_id]
        elif event.type == TRANSFER:
            entry = self.capture.transfer_index[event.id]
            traffic = self.capture.endpoint_traffic[entry.endpoint_id]
            transfer = traffic.transfers[entry.transfer_id]
            transaction_id = traffic.transaction_ids[transfer.ep_tran_offset]
            transaction = self.capture.transactions[transaction_id]
            packet_id = transaction.first_packet_id
            packet = self.capture.packets[packet_id]

        if col == self.TIMESTAMP:
            offset_ns = packet.timestamp_ns - self.capture.packets[0].timestamp_ns
            return "%.9f" % (offset_ns / 1e9)

        if col == self.SUBTYPE:
            if event.type in (PACKET, TRANSACTION):
                return pid_names[packet.pid & PID_MASK]
            elif event.type == TRANSFER:
                if packet.pid == SETUP:
                    return "CONTROL"
                elif packet.pid == IN:
                    return "BULK IN"
                elif packet.pid == OUT:
                    return "BULK OUT"
