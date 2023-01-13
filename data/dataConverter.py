import pyshark
import pandas as pd

pcap_path = '../model/test_capture.pcapng'
# For reading PCAP file
pcap = pyshark.FileCapture(pcap_path)
# We can add filters like this -> pyshark.FileCapture(pcap_path, display_filter="dns")
pcap = pyshark.FileCapture(pcap_path)
data = []

# Packet manipulation
for packet in pcap:
    print('-----------------')
    # get_multiple_layers allows to select what layer from the packet do you want to analyze.
    #print(packet.get_multiple_layers('DNS')[0])
    protocol = packet.transport_layer
    if 'IP' in packet and hasattr(packet, 'tcp') or hasattr(packet, 'udp'):
        src_address = packet.ip.src
        src_port = packet[protocol].srcport
        dst_address = packet.ip.dst
        dst_port = packet[protocol].dstport
        length = packet.length
        packet_info = [protocol, src_address, src_port, dst_address, dst_port, length]
        data.append(packet_info)
        print(dst_port)
df = pd.DataFrame(data, columns=['Protocol', 'Source Address', 'Source Port', 'Destination Address',
                                 'Destination Port', 'Length'])






