import pyshark

def capture_live_packets(network_interface):
    capture = pyshark.LiveCapture(interface=network_interface, display_filter="dns")
    i=0
    for raw_packet in capture.sniff_continuously():
        print('--------------------')
        print(filter_all_tcp_traffic_file(raw_packet))
        print('--------------------')


def filter_all_tcp_traffic_file(packet):
    """
    This function is designed to parse all the Transmission Control Protocol(TCP) packets
    :param packet: raw packet
    :return: specific packet details
    """

    if packet.get_multiple_layers('DNS')[0]:
        return packet.dns.qry_name

capture_live_packets('Ethernet')