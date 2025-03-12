from scapy.all import *

def pcap_reader(file):

    for idx, pkt in enumerate(PcapReader(file)):

        print(pkt)
        if idx == 10:
            break


if __name__ == '__main__':

    file1 = 'Data_Research/attack_1.pcap'

    pcap_reader(file1)

