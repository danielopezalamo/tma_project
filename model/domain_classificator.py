import pyshark

pcap_path = './test_capture.pcapng'

# For reading PCAP file
pcap = pyshark.FileCapture(pcap_path)

pcap = pyshark.FileCapture(pcap_path, display_filter="dns")

for packet in pcap:
    print(packet.get_multiple_layers('DNS')[0])
    print('-----------------')