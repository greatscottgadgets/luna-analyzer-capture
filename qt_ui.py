from PySide6.QtCore import Qt, QCoreApplication
from PySide6.QtWidgets import QApplication, QHeaderView, QTableView
from PySide6.QtUiTools import QUiLoader
from qt_tablemodels import *
from qt_treemodel import *
from interface import *
import faulthandler
import sys

faulthandler.enable()

if len(sys.argv) != 2:
    print("Usage: %s <capture file>" % sys.argv[0])
    sys.exit(-1)

# Load capture
capture = convert_capture(sys.argv[1].encode('ascii'))

# Set up and run UI
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
