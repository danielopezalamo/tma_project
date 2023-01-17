import pyshark

def capture_live_packets(network_interface):
    capture = pyshark.LiveCapture(interface=network_interface, display_filter="dns")
    for packet in capture.sniff_continuously():
        print(packet.dns.qry_name)

capture_live_packets('Ethernet')