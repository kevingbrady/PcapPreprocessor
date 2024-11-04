import multiprocessing
import os
import sys

# sys.stderr = None  # suppress stderr
from scapy.all import *

# sys.stderr = sys.__stderr__  # restore stderr

from src.data_columns import columns
from src.PacketCounter import PacketCounter
from src.FlowMeterMetrics import FlowMeterMetrics
from src.utils import pretty_time_delta
from multiprocessing import Pool, Manager, cpu_count
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import numpy as np
import csv

np.set_printoptions(linewidth=200000)


class Sniffer:
    file_count = 0
    file_sizes = []

    def __init__(self, output_file):

        manager = Manager()
        self.completed = manager.list()
        self.in_progress = manager.list()

        self.total_packets = manager.Value('i', 0)
        self.index = manager.Value('i', 0)

        self.write_lock = manager.Lock()

        self.output_file = output_file
        self.columns = columns

    def run_sniffer(self, file):

        self.in_progress.append(file)
        self.display_progress()
        logging.info('Parsing file: ' + file)

        target = 0

        if file.lower().__contains__('attack'):
            target = 1

        packets = PcapReader(file)
        counter = PacketCounter()
        packet_data = {}
        flow_meter = FlowMeterMetrics(output_mode="flow")

        for pkt in packets:

            counter.packet_count_total += 1

            if ('IP' in pkt) or ('IPv6' in pkt):
                if ('TCP' in pkt) or ('UDP' in pkt):
                    flow, direction = flow_meter.process_packet(pkt)
                    flow_metrics = flow.get_data(direction)

                    flow_metrics['Target'] = target

                    if flow.key not in packet_data:
                        packet_data.update({flow.key: [flow_metrics]})
                    else:
                        packet_data[flow.key].append(flow_metrics)

                    '''
                    magic_char = '\033[F'
                    os.system('cls||clear')
                    output = ''.join([str(flow.key) + ': ' + flow.get_short_flow_output() for key, flow in flow_meter.flows.items()])
                    display_flow_count = output.count('\n')
                    ret_depth = magic_char * display_flow_count
                    print('{}{}'.format(ret_depth, output), flush=True, end='')
                    print(display_flow_count, "flows recorded ...")
                    time.sleep(0.15)
                    '''
                    # print(next(iter(flow_meter.flows.items())))

        self.total_packets.value += counter.get_packet_count_total()
        self.in_progress.remove(file)
        self.completed.append(file)
        self.display_progress()

        logging.info('File completed: ' + file)

        # Append data to final CSV file

        self.write_lock.acquire()
        self.write_data_to_csv(packet_data, self.output_file)
        self.write_lock.release()

        return 0

    def start_sniffer(self, file_list, parallel=False):

        self.file_count = len(file_list)

        if parallel:

            with ProcessPoolExecutor(max_tasks_per_child=1) as pool:
                # Sort file_list by file size so the program processes the largest files first
                results = pool.map(self.run_sniffer, sorted(file_list, key=lambda file: os.path.getsize(file), reverse=True))

        else:
            results = [self.run_sniffer(file) for file in file_list]
            #results = self.run_sniffer(file_list[0])

        return results

    def write_data_to_csv(self, data, output_file):

        mode = 'w' if self.index.value == 0 else 'a'

        with open(output_file, mode=mode, newline='') as csv_file:

            writer = csv.DictWriter(csv_file, fieldnames=self.columns)
            if mode == 'w':
                writer.writeheader()

            for key, group in data.items():
                self.index.value += len(group)
                writer.writerows([flow for flow in group])

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
