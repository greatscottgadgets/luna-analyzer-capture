This repository contains some prototype code for [Packetry](https://github.com/greatscottgadgets/packetry/) that works with [LUNA's](https://github.com/greatscottgadgets/luna/) USB analyzer mode.

To build, run `make`.

Programs included are:

- `setup-analyzer.py`: builds gateware and configures LUNA as a USB analyzer, then exits.
- `capture`: captures the raw packet stream from LUNA and writes it to standard output.
- `decode_test`: reads packet stream from a file and decodes it into data structures.
- `qt_ui.py`: prototype UI in Qt, reads packet stream from a file.
- `gtk_ui.py`: prototype UI in GTK, reads packet stream from a file.
- `luna2pcap`: reads packet stream from standard input, and writes to standard output in pcap format.

 
