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
from multiprocessing import Pool
import numpy as np
import csv

np.set_printoptions(linewidth=200000)


class Sniffer:

    keep_incomplete = False
    enable_cicflowmeter = False
    file_count = 0
    file_sizes = []

    def __init__(self, manager, keep_incomplete, enable_cicflowmeter, output_file, columns):

        self.manager = manager
        self.manager.columns = columns
        self.flow_meter = manager.FlowMeterMetrics(output_mode="flow")

        self.keep_incomplete = keep_incomplete
        self.enable_cicflowmeter = enable_cicflowmeter
        self.output_file = output_file
        self.columns = columns

    def run_sniffer(self, filename):

        self.manager.in_progress.append(filename)
        self.display_progress()
        logging.info('Parsing file: ' + filename)

        target = 0

        if filename.lower().__contains__('attack'):
            target = 1

        packets = PcapReader(filename)
        counter = PacketCounter()
        packet_data = []

        for pkt in packets:
            if counter.get_packet_count_total() == 0:
                self.manager.start_time.value = pkt.time

            counter.packet_count_total += 1

            if self.enable_cicflowmeter:

                if pkt.haslayer('IP') or pkt.haslayer('IPv6'):
                    if pkt.haslayer('TCP') or pkt.haslayer('UDP'):

                        flow, direction = self.flow_meter.process_packet(pkt)
                        flow_metrics = flow.get_data(pkt, direction)

                        flow_metrics['Target'] = target
                        packet_data.append(flow_metrics)

                    # print(packet_data[-1])

            else:
                pkt.frame = counter.get_packet_count_preprocessed()
                time_elapsed = pkt.time - self.manager.start_time.value
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

        self.manager.total_packets.value += counter.get_packet_count_total()
        self.manager.in_progress.remove(filename)
        self.manager.completed.append(filename)
        self.display_progress()

        logging.info('File completed: ' + filename)

        # Append data to final CSV file

        self.manager.write_data_to_csv(packet_data)

    def start_sniffer(self, file_list):

        if type(file_list) is str:

            self.file_count = 1
            self.run_sniffer(file_list)

        else:

            self.file_count = len(file_list)
            with Pool(os.cpu_count()) as pool:

                pool.map(self.run_sniffer, file_list)

    def display_progress(self):

        print('\x1b[2K\r')
        print('-------------------------------------------------------------------------------------------------')
        print('IN PROGRESS  [' + str(self.file_count - len(self.manager.completed) - len(
            self.manager.in_progress)) + ' files waiting to be processed]' + '\n' + str(
            [i for i in self.manager.in_progress]) + '\n\n' + 'COMPLETED  [' + str(len(self.manager.completed)) + '/' + str(
            self.file_count) + ']' + '\n' + str([i for i in self.manager.completed]))
        print('-------------------------------------------------------------------------------------------------')
        time.sleep(0.25)

    def print_end_message(self, elapsed_time):

        print("Preprocessed " + str(self.manager.index.value) + " out of " + str(
            self.manager.total_packets.value) + " total packets in " + pretty_time_delta(elapsed_time))
        print("Program End")
