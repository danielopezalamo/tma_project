import pyshark

pcap_path = 'model/test_capture.pcapng'
# For reading PCAP file
pcap = pyshark.FileCapture(pcap_path)
# We can add filters like this -> pyshark.FileCapture(pcap_path, display_filter="dns")
pcap = pyshark.FileCapture(pcap_path, display_filter="dns")

# Packet manipulation 
for packet in pcap:
    print('-----------------')
    # get_multiple_layers allows to select what layer from the packet do you want to analyze.
    print(packet.get_multiple_layers('DNS')[0])
    print('-----------------')



