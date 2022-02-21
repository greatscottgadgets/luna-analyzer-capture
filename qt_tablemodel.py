from PySide6.QtCore import Qt, QAbstractItemModel, QModelIndex
from treeitem import EventTreeItem
from interface import *

# Tree model for events
class EventTreeModel(QAbstractItemModel):

    cols = ["Event"]

    def __init__(self, parent, capture):
        super().__init__(parent)
        self.root_item = EventTreeItem.root(capture)

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
        return len(self.cols)

    def headerData(self,section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.cols[section]
        return None

    def flags(self, index):
        if not index.isValid():
            return Qt.NoItemFlags
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable

    def index(self, row, column, parent):
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        child_item = self.item(parent).child_item(row)
        if child_item:
            return self.createIndex(row, column, child_item)
        else:
            return QModelIndex()

    def parent(self, index):
        item = self.item(index)
        if self.root_item in (item, item.parent):
            return QModelIndex()
        if item.parent.parent:
            parent_index = item.parent.child_index
        else:
            parent_index = 0
        return self.createIndex(parent_index, 0, item.parent)

    def data(self, index, role):
        if role == Qt.DisplayRole:
            return self.item(index).data(index.column())
