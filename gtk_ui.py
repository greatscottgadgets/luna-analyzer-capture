import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GObject
from treeitem import EventTreeItem
from gtk_treemodel import *
from interface import *
import faulthandler
import sys

faulthandler.enable()

if len(sys.argv) != 2:
    print("Usage: %s <capture file>" % sys.argv[0])
    sys.exit(-1)

# Load capture
capture = convert_capture(sys.argv[1].encode('ascii'))

# Set up and run GUI
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
