import sys
sys.stderr = None  # suppress stderr
from scapy.all import *
import scapy.layers.inet as inet
sys.stderr = sys.__stderr__       # restore stderr

from PacketCounter import PacketCounter
from clean_ip import _format_ip
import time
import pandas as pd
import multiprocessing


class Sniffer:

    keep_incomplete = False

    def __init__(self, manager):

        self.in_progress = manager.list()
        self.completed = manager.list()
        self.file_count = 0
        self.total_packets = manager.Value('i', 0)

    def run_sniffer(self, filename):

        self.in_progress.append(filename)
        self.display_progress()
        logging.info('Parsing file: ' + filename)

        packets = rdpcap(filename)
        counter = PacketCounter()
        packet_data = []

        self.total_packets.value += len(packets)

        for pkt in packets:
            if counter.get_packet_count() == 0:
                counter.set_start_time(pkt.time)

            counter.increment()
            pkt.frame = counter.get_packet_count()
            time_elapsed = pkt.time - counter.get_start_time()
            pkt_length = pkt.wirelen
            ip_src = None
            ip_dst = None
            protocol = None
            info = 0  # ACK is only present in TCP packets

            if inet.IP in pkt:
                cleaned_ip_src = _format_ip(pkt[inet.IP].src, "auto", "integer", "raise")
                cleaned_ip_dst = _format_ip(pkt[inet.IP].dst, "auto", "integer", "raise")
                ip_src = cleaned_ip_src[0]
                ip_dst = cleaned_ip_dst[0]
                protocol = pkt[inet.IP].proto

            if inet.TCP in pkt:
                info = pkt[inet.TCP].ack

            target = 0

            if filename.lower().__contains__('attack'):
                target = 1

            # if gl_args.verbose:
            #    print(pkt.frame, time_elapsed, ip_src, ip_dst, protocol, pkt_length, info, target, end='\n')

            if None not in (time_elapsed, ip_src, ip_dst, protocol, info) or self.keep_incomplete:
                packet_data.append([pkt.frame, time_elapsed, ip_src, ip_dst, protocol, pkt_length, info, target])

        self.in_progress.remove(filename)
        self.completed.append(filename)
        self.display_progress()

        logging.info('File completed: ' + filename)

        new_frame = pd.DataFrame(packet_data, columns=['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info', 'Target'])
        return new_frame

    def start_sniffer(self, files):

        self.file_count = len(files)

        with multiprocessing.Pool(os.cpu_count()) as pool:

            data = pd.concat(pool.map(self.run_sniffer, files), ignore_index=True)
            return data

    def display_progress(self):

        print('\x1b[2K\r')
        print('-------------------------------------------------------------------------------------------------')
        print('IN PROGRESS  [' + str(self.file_count - len(self.completed) - len(self.in_progress)) + ' files waiting to be processed]' + '\n' + str([i for i in self.in_progress]) + '\n\n' + 'COMPLETED  [' + str(len(self.completed)) + '/' + str(self.file_count) + ']' + '\n' + str([i for i in self.completed]))
        print('-------------------------------------------------------------------------------------------------')
        time.sleep(0.25)
