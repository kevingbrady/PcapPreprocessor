import sys

# sys.stderr = None  # suppress stderr
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

# sys.stderr = sys.__stderr__  # restore stderr

from src.PacketCounter import PacketCounter
from src.FlowMeterMetrics import FlowMeterMetrics
from src.clean_ip import _format_ip
from src.utils import pretty_time_delta
import pandas as pd
from multiprocessing import Pool, Manager
import numpy as np
import csv

np.set_printoptions(linewidth=200000)


class Sniffer:

    keep_incomplete = False
    enable_cicflowmeter = False
    file_count = 0
    file_sizes = []

    def __init__(self, keep_incomplete, enable_cicflowmeter, output_file, columns):

        manager = Manager()

        self.completed = manager.list()
        self.in_progress = manager.list()

        self.total_packets = manager.Value('i', 0)
        self.index = manager.Value('i', 0)

        self.write_lock = manager.Lock()

        self.keep_incomplete = keep_incomplete
        self.enable_cicflowmeter = enable_cicflowmeter
        self.output_file = output_file
        self.columns = columns

    def run_sniffer(self, filename):

        self.in_progress.append(filename)
        self.display_progress()
        logging.info('Parsing file: ' + filename)

        start_time = 0
        target = 0

        if filename.lower().__contains__('attack'):
            target = 1

        flow_meter = FlowMeterMetrics(output_mode="flow")
        packets = PcapReader(filename)
        counter = PacketCounter()
        packet_data = []

        for pkt in packets:
            if counter.get_packet_count_total() == 0:
                start_time = pkt.time

            counter.packet_count_total += 1

            if self.enable_cicflowmeter:

                if pkt.haslayer('IP') or pkt.haslayer('IPv6'):
                    if pkt.haslayer('TCP') or pkt.haslayer('UDP'):

                        flow, direction = flow_meter.process_packet(pkt)
                        flow_metrics = flow.get_data(direction)

                        flow_metrics['Target'] = target
                        packet_data.append(flow_metrics)

                    # print(packet_data[-1])

            else:
                pkt.frame = counter.get_packet_count_preprocessed()
                time_elapsed = pkt.time - start_time
                pkt_length = pkt.wirelen
                ip_src = None
                ip_dst = None
                protocol = None
                info = 0  # ACK is only present in TCP packets

                if IP in pkt:
                    cleaned_ip_src = _format_ip(pkt[IP].src, "auto", "integer", "raise")
                    cleaned_ip_dst = _format_ip(pkt[IP].dst, "auto", "integer", "raise")
                    ip_src = cleaned_ip_src[0]
                    ip_dst = cleaned_ip_dst[0]
                    protocol = pkt[IP].proto

                if TCP in pkt:
                    info = pkt[TCP].ack

                # if gl_args.verbose:
                #    print(pkt.frame, time_elapsed, ip_src, ip_dst, protocol, pkt_length, info, target, end='\n')

                if None not in (time_elapsed, ip_src, ip_dst, protocol, info) or self.keep_incomplete:
                    packet_data.append([pkt.frame, time_elapsed, ip_src, ip_dst, protocol, pkt_length, info, target])
                    counter.packet_count_preprocessed += 1

        self.total_packets.value += counter.get_packet_count_total()
        self.in_progress.remove(filename)
        self.completed.append(filename)
        self.display_progress()

        logging.info('File completed: ' + filename)

        # Append data to final CSV file

        self.write_lock.acquire()
        self.write_data_to_csv(packet_data)
        self.write_lock.release()

    def start_sniffer(self, file_list, parallel=False):

        self.file_count = len(file_list)

        if parallel:

            with Pool(os.cpu_count()) as pool:

                pool.map(self.run_sniffer, file_list)

        else:

            for file in file_list:
                self.run_sniffer(file)

    def write_data_to_csv(self, data, output_file):

        header = True if self.index.value == 0 else False
        mode = 'w' if self.index.value == 0 else 'a'

        new_frame = pd.DataFrame(data, columns=self.columns)
        new_frame.index += self.index.value
        new_frame.to_csv(output_file, mode=mode, header=header, index_label='No')
        self.index.value += len(data)

    def display_progress(self):

        print('\x1b[2K\r')
        print('-------------------------------------------------------------------------------------------------')
        print('IN PROGRESS  [' + str(self.file_count - len(self.completed) - len(
            self.in_progress)) + ' files waiting to be processed]' + '\n' + str(
            [i for i in self.in_progress]) + '\n\n' + 'COMPLETED  [' + str(len(self.completed)) + '/' + str(
            self.file_count) + ']' + '\n' + str([i for i in self.completed]))
        print('-------------------------------------------------------------------------------------------------')
        time.sleep(0.25)

    def print_end_message(self, elapsed_time):

        print("Preprocessed " + str(self.index.value) + " out of " + str(
            self.total_packets.value) + " total packets in " + pretty_time_delta(elapsed_time))
        print("Program End")
