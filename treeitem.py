from interface import *

# An item in the event tree. May be the root, a transfer,
# a transaction or a packet. Created on demand as nodes
# of the tree are accessed.

class EventTreeItem(object):

    # Construct a tree item.
    #
    # capture: FFI handle for capture structure
    # parent: EventTreeItem object
    # item_type: TRANSFER, TRANSACTION or PACKET
    # item_id: index of this item's data in the capture
    # child_index: index of this item within its parent item
    #
    def __init__(self, capture, parent, item_type, item_id, child_index):
        self.capture = capture
        self.parent = parent
        self.item_type = item_type
        self.item_id = item_id
        self.child_index = child_index
        self.child_cache = {}

    # Construct the root item.
    @classmethod
    def root(cls, capture):
        return EventTreeItem(capture, None, None, None, None)

    # Number of children under this item.
    def child_count(self):
        if self.parent is None:
            return self.capture.num_events
        elif self.item_type == TRANSFER:
            entry = self.capture.transfer_index[self.item_id]
            traffic = self.capture.endpoint_traffic[entry.endpoint_id]
            transfer = traffic.transfers[entry.transfer_id]
            return transfer.num_transactions
        elif self.item_type == TRANSACTION:
            transaction = self.capture.transactions[self.item_id]
            return transaction.num_packets
        elif self.item_type == PACKET:
            return 0

    # Construct a child of this item.
    def child_item(self, child_index):
        if child := self.child_cache.get(child_index):
            return child
        if self.parent is None:
            event = self.capture.events[child_index]
            child_type = event.type
            child_id = event.id
        elif self.item_type == TRANSFER:
            child_type = TRANSACTION
            entry = self.capture.transfer_index[self.item_id]
            traffic = self.capture.endpoint_traffic[entry.endpoint_id]
            transfer = traffic.transfers[entry.transfer_id]
            child_id = traffic.transaction_ids[transfer.ep_tran_offset + child_index]
        elif self.item_type == TRANSACTION:
            child_type = PACKET
            transaction = self.capture.transactions[self.item_id]
            child_id = transaction.first_packet_id + child_index
        child = EventTreeItem(self.capture, self, child_type, child_id, child_index)
        self.child_cache[child_index] = child
        return child

    # Get data to display for this item.
    def data(self, col):
        if col != 0:
            return None
        if self.item_type == TRANSFER:
            entry = self.capture.transfer_index[self.item_id]
            ep = self.capture.endpoints[entry.endpoint_id]
            traffic = self.capture.endpoint_traffic[entry.endpoint_id]
            transfer = traffic.transfers[entry.transfer_id]
            first_transaction_id = traffic.transaction_ids[transfer.ep_tran_offset]
            first_transaction = self.capture.transactions[first_transaction_id]
            first_packet = self.capture.packets[first_transaction.first_packet_id]
            if first_packet.pid == SETUP:
                fmt = "Control transfer on %u.%u with %u transactions"
            elif first_packet.pid == IN:
                fmt = "Bulk transfer from %u.%u to host with %u transactions"
            elif first_packet.pid == OUT:
                fmt = "Bulk transfer from host to %u.%u with %u trasactions"
            return fmt % (ep.address, ep.endpoint_num, transfer.num_transactions)
        elif self.item_type == TRANSACTION:
            transaction = self.capture.transactions[self.item_id]
            first_packet = self.capture.packets[transaction.first_packet_id]
            if first_packet.pid == SOF:
                return "Idle period with %u SOF packets" % transaction.num_packets
            name = pid_names[first_packet.pid & PID_MASK]
            return "%s transaction, %u packets" % (name, transaction.num_packets)
        elif self.item_type == PACKET:
            packet = self.capture.packets[self.item_id]
            name = pid_names[packet.pid & PID_MASK]
            return "%s packet, %u bytes" % (name, packet.length)
