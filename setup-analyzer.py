from luna.gateware.applets.analyzer import USBAnalyzerConnection, USB_SPEED_HIGH
analyzer = USBAnalyzerConnection()
analyzer.build_and_configure(USB_SPEED_HIGH)
