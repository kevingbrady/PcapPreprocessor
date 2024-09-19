import psutil
import time
from datetime import datetime
from scapy.all import *
from src.utils import pretty_time_delta


class PacketCapture:

    total_packets = 0
    start_time = 0

    def __init__(self, interfaces=None):

        self.ifaces = []
        self.file = "benign-data-capture-" + str(datetime.now()) + ".pcap"

        if interfaces is None:
            iface_dict = psutil.net_if_stats()
            for key, value in iface_dict.items():
                if (key != 'lo') and (value.isup is True):
                    self.ifaces.append(key)

        else:
            self.ifaces = interfaces

        print(self.ifaces)

    def run_sniffer(self):
        
        try:

            sniffer = AsyncSniffer(iface=self.ifaces, prn=self.process_packet, store=False)
            sniffer.start()
            sniffer.join()

        except KeyboardInterrupt:
            elapsed_time = time.time() - self.start_time
            print(
                "\nSniffed %d packets in %s" % (
                    self.total_packets, pretty_time_delta(elapsed_time)
                ))

            raise KeyboardInterrupt

    def process_packet(self, pkt):

        if self.start_time == 0:
            self.start_time = time.time()

        wrpcap(self.file, pkt, append=True)
        self.total_packets += 1


if __name__ == '__main__':

    capture = PacketCapture()
    capture.run_sniffer()
