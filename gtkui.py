import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GObject

from interface import *

import faulthandler
import sys

faulthandler.enable()

pid_names = [
        "RSVD", "OUT", "ACK", "DATA0",
        "PING", "SOF", "NYET", "DATA2",
        "SPLIT", "IN", "NAK", "DATA1",
        "ERR", "SETUP", "STALL", "MDATA"]

event_names = ["PKT", "TRN", "XFR"]

# An item in the event tree. May be the root, a transfer,
# a transaction or a packet. Created on demand as nodes
# of the tree are accessed.

class EventTreeItem(object):

    # Hack to allow us to retrieve existing items by their python id(),
    # which we can stash in the user_data of a Gtk.TreeIter. Also makes
    # sure that we hold a reference to stop items being garbage collected.
    cache = {}

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
        self.cache[id(self)] = self
        self.child_cache = {}

    # Construct the root item.
    @classmethod
    def root(cls, capture):
        return EventTreeItem(capture, None, None, None, None)

    # Retrieve EventTreeItem from a Gtk.TreeIter.
    @classmethod
    def retrieve(self, iterator):
        return self.cache[iterator.user_data]

    # Store a reference to this item in a Gtk.TreeIter.
    def store(self, iterator):
        iterator.user_data = id(self)

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
            child_id = event.index
        elif self.item_type == TRANSFER:
            child_type = TRANSACTION
            entry = self.capture.transfer_index[self.item_id]
            traffic = self.capture.endpoint_traffic[entry.endpoint_id]
            transfer = traffic.transfers[entry.transfer_id]
            child_id = traffic.transaction_ids[transfer.id_offset + child_index]
        elif self.item_type == TRANSACTION:
            child_type = PACKET
            transaction = self.capture.transactions[self.item_id]
            child_id = transaction.first_packet_index + child_index
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
            first_transaction_id = traffic.transaction_ids[transfer.id_offset]
            first_transaction = self.capture.transactions[first_transaction_id]
            first_packet = self.capture.packets[first_transaction.first_packet_index]
            if first_packet.pid == SETUP:
                fmt = "Control transfer on %u.%u with %u transactions"
            elif first_packet.pid == IN:
                fmt = "Bulk transfer from %u.%u to host with %u transactions"
            elif first_packet.pid == OUT:
                fmt = "Bulk transfer from host to %u.%u with %u trasactions"
            else:
                return "Unexpected transfer start PID %s" % pid_names[packet.pid & 0x03]
            return fmt % (ep.address, ep.endpoint, transfer.num_transactions)
        elif self.item_type == TRANSACTION:
            transaction = self.capture.transactions[self.item_id]
            first_packet = self.capture.packets[transaction.first_packet_index]
            if first_packet.pid == SOF:
                return "Idle period with %u SOF packets" % transaction.num_packets
            name = pid_names[first_packet.pid & 0b1111]
            return "%s transaction, %u packets" % (name, transaction.num_packets)
        elif self.item_type == PACKET:
            packet = self.capture.packets[self.item_id]
            name = pid_names[packet.pid & 0b1111]
            return "%s packet, %u bytes" % (name, packet.length)


# Implementation of Gtk.TreeModel interface.

class EventTreeModel(GObject.GObject, Gtk.TreeModel):

    def __init__(self, capture):
        super().__init__()
        self.capture = capture
        self.root_item = EventTreeItem.root(capture)

    def do_get_n_columns(self):
        return 1

    def do_get_column_type(self, index):
        return str

    def do_get_path(self, iterator):
        item = EventTreeItem.retrieve(iterator)
        path = Gtk.TreePath()
        while item.child_index is not None:
            path.prepend_index(item.child_index)
            item = item.parent
        return path

    def do_get_iter(self, path):
        indices = path.get_indices()
        depth = path.get_depth()
        item = self.root_item
        for index in indices[:depth]:
            if index >= item.child_count():
                return (False, None)
            item = item.child_item(index)
        iterator = Gtk.TreeIter()
        item.store(iterator)
        return (True, iterator)

    def do_iter_next(self, iterator):
        item = EventTreeItem.retrieve(iterator)
        if item.parent is None:
            return False
        if item.child_index >= item.parent.child_count() - 1:
            return False
        next_item = item.parent.child_item(item.child_index + 1)
        next_item.store(iterator)
        return True

    def do_iter_prev(self, iterator):
        item = EventTreeItem.retrieve(iterator)
        if item.parent is None:
            return False
        if item.child_index <= 0:
            return False
        prev_item = item.parent.child_item(item.child_index - 1)
        prev_item.store(iterator)
        return True

    def do_iter_has_child(self, iterator):
        item = EventTreeItem.retrieve(iterator)
        return item.child_count() > 0

    def do_iter_n_children(self, iterator):
        item = EventTreeItem.retrieve(iterator)
        return item.child_count()

    def do_iter_children(self, parent):
        if parent is None:
            parent_item = self.root_item
        else:
            parent_item = EventTreeItem.retrieve(parent)
        if parent_item.child_count() == 0:
            return (False, None)
        child_item = parent_item.child_item(0)
        iterator = Gtk.TreeIter()
        child_item.store(iterator)
        return (True, iterator)

    def do_iter_nth_child(self, parent, n):
        if parent is None:
            parent_item = self.root_item
        else:
            parent_item = EventTreeItem.retrieve(parent)
        if n >= parent_item.child_count():
            return (False, None)
        child_item = parent_item.child_item(n)
        iterator = Gtk.TreeIter()
        child_item.store(iterator)
        return (True, iterator)

    def do_iter_parent(self, child):
        item = EventTreeItem.retrieve(child)
        if item.parent is None:
            return (False, None)
        iterator = Gtk.TreeIter()
        item.parent.store(iterator)
        return (True, iterator)

    def do_get_value(self, iterator, column):
        item = EventTreeItem.retrieve(iterator)
        return item.data(column)


capture = convert_capture(sys.argv[1].encode('ascii'))
model = EventTreeModel(capture)
builder = Gtk.Builder()
builder.add_from_file("analyzer.glade")
window = builder.get_object("window")
window.connect('destroy', lambda *a: Gtk.main_quit())
view = builder.get_object("view")
view.set_model(model)
view.append_column(Gtk.TreeViewColumn('Event', Gtk.CellRendererText(), text=0))
window.show_all()
Gtk.main()
