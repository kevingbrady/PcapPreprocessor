import os

from scapy.all import *
from src.data_columns import columns
from src.PacketCounter import PacketCounter
from src.FlowMeterMetrics import FlowMeterMetrics
from src.utils import pretty_time_delta
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import csv


class Sniffer:
    file_count = 0
    file_sizes = []

    def __init__(self, output_file):

        manager = Manager()
        self.completed = []
        self.in_progress = []

        self.total_packets = 0
        self.index = 0

        self.write_lock = manager.Lock()
        self.output_file = output_file
        self.display_output = ''

    def run_sniffer(self, file) -> int:

        logging.info('Parsing file: ' + file)
        self.in_progress.append(file)
        self.display_progress()

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
                    counter.packet_count_preprocessed += 1
                    flow, direction = flow_meter.process_packet(pkt)
                    flow_metrics = flow.get_data(direction)
                    flow_metrics['Target'] = target

                    if flow.key not in packet_data:
                        packet_data.update({flow.key: [flow_metrics, ]})
                    else:
                        packet_data[flow.key].append(flow_metrics)

        # Append data to final CSV file

        self.write_lock.acquire()

        self.write_data_to_csv(packet_data, self.output_file)
        self.index += counter.get_packet_count_preprocessed()
        self.total_packets += counter.get_packet_count_total()
        self.in_progress.remove(file)
        self.completed.append(file)

        self.write_lock.release()
        self.display_progress()

        logging.info('File completed: ' + file)

        return 0

    def start_sniffer(self, file_list, parallel=False) -> list:

        if type(file_list) is str:
            self.file_count = 1
            results = self.run_sniffer(file_list)

        elif type(file_list) is list:

            self.file_count = len(file_list)
            if parallel:

                with ThreadPoolExecutor() as pool:
                    # Sort file_list by file size so the program processes the largest files first
                    results = pool.map(self.run_sniffer, file_list)

            else:
                results = [self.run_sniffer(file) for file in file_list]

        return results

    def write_data_to_csv(self, data, output_file) -> None:

        mode = 'w' if self.index == 0 else 'a'

        with open(output_file, mode=mode, newline='') as csv_file:

            writer = csv.DictWriter(csv_file, fieldnames=columns.keys())
            if mode == 'w':
                writer.writeheader()

            for key, group in data.items():

                for flow in group:
                    for k in flow:
                        if type(flow[k]) not in (str, int) and flow[k] > 0:
                            flow[k] = format(flow[k], ".8f")
                    writer.writerow(flow)

    def display_progress(self) -> None:

        sep = ('-' * os.get_terminal_size().columns) + '\n'

        magic_char = '\033[F'
        os.system('cls||clear')

        waiting = str(self.file_count - len(self.completed) - len(self.in_progress))
        complete_count = str(len(self.completed)) + '/' + str(self.file_count)
        in_progress = str([i for i in self.in_progress])
        completed = str([i for i in self.completed])

        self.display_output = f"{sep}IN PROGRESS [{waiting} files waiting to be processed]\n {in_progress} \n\nCOMPLETED [{complete_count}]\n {completed}\n{sep}"
        new_line_count = self.display_output.count('\n')
        ret_depth = magic_char * new_line_count
        print('{}{}'.format(ret_depth, self.display_output), flush=True, end='')

    def print_end_message(self, elapsed_time) -> None:

        output = f"\n\nPreprocessed {self.index} out of {self.total_packets} total packets in {pretty_time_delta(elapsed_time)}\nProgram End"
        print(output)
