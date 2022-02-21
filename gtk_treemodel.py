import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GObject
from treeitem import EventTreeItem

# Implementation of Gtk.TreeModel interface.
class EventTreeModel(GObject.GObject, Gtk.TreeModel):

    # Hack to allow us to retrieve existing items by their python id(),
    # which we can stash in the user_data of a Gtk.TreeIter. Also makes
    # sure that we hold a reference to stop items being garbage collected.
    cache = {}

    def __init__(self, capture):
        super().__init__()
        self.capture = capture
        self.root_item = EventTreeItem.root(capture)
        self.cache[id(self.root_item)] = self.root_item

    # Retrieve EventTreeItem from a Gtk.TreeIter.
    @classmethod
    def retrieve(self, iterator):
        return self.cache[iterator.user_data]

    # Store a reference to this item in a Gtk.TreeIter.
    def store(self, item, iterator):
        self.cache[id(item)] = item
        iterator.user_data = id(item)

    def do_get_n_columns(self):
        return 1

    def do_get_column_type(self, index):
        return str

    def do_get_path(self, iterator):
        item = self.retrieve(iterator)
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
        self.store(item, iterator)
        return (True, iterator)

    def do_iter_next(self, iterator):
        item = self.retrieve(iterator)
        if item.parent is None:
            return False
        if item.child_index >= item.parent.child_count() - 1:
            return False
        next_item = item.parent.child_item(item.child_index + 1)
        self.store(next_item, iterator)
        return True

    def do_iter_prev(self, iterator):
        item = self.retrieve(iterator)
        if item.parent is None:
            return False
        if item.child_index <= 0:
            return False
        prev_item = item.parent.child_item(item.child_index - 1)
        self.store(prev_item, iterator)
        return True

    def do_iter_has_child(self, iterator):
        item = self.retrieve(iterator)
        return item.child_count() > 0

    def do_iter_n_children(self, iterator):
        item = self.retrieve(iterator)
        return item.child_count()

    def do_iter_children(self, parent):
        if parent is None:
            parent_item = self.root_item
        else:
            parent_item = self.retrieve(parent)
        if parent_item.child_count() == 0:
            return (False, None)
        child_item = parent_item.child_item(0)
        iterator = Gtk.TreeIter()
        self.store(child_item, iterator)
        return (True, iterator)

    def do_iter_nth_child(self, parent, n):
        if parent is None:
            parent_item = self.root_item
        else:
            parent_item = self.retrieve(parent)
        if n >= parent_item.child_count():
            return (False, None)
        child_item = parent_item.child_item(n)
        iterator = Gtk.TreeIter()
        self.store(child_item, iterator)
        return (True, iterator)

    def do_iter_parent(self, child):
        item = self.retrieve(child)
        if item.parent is None:
            return (False, None)
        iterator = Gtk.TreeIter()
        self.store(item.parent, iterator)
        return (True, iterator)

    def do_get_value(self, iterator, column):
        item = self.retrieve(iterator)
        return item.data(column)
