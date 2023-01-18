import pyshark

pcap_path = './test2.pcapng'

# For reading PCAP file
pcap = pyshark.FileCapture(pcap_path)

pcap = pyshark.FileCapture(pcap_path, display_filter="http")

for packet in pcap:
    print(packet.http.get_field('http.request.full_uri'))
    print('-----------------')