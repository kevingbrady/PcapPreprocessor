from scapy.all import *
from src.data_columns import columns
from src.PacketCounter import PacketCounter
from src.FlowMeterMetrics import FlowMeterMetrics
from src.utils import pretty_time_delta
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor
import numpy as np
import csv
import torch
from torch_geometric.data import Data


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

    def run_sniffer(self, file) -> int:

        logging.info('Parsing file: ' + file)
        self.in_progress.append(file)
        #self.display_progress()

        target = 0

        if file.lower().__contains__('attack'):
            target = 1

        packets = PcapReader(file)
        counter = PacketCounter()
        graph_snapshots = []
        flow_meter = FlowMeterMetrics(output_mode="flow")

        for pkt in packets:

            counter.packet_count_total += 1

            if ('IP' in pkt) or ('IPv6' in pkt):
                if ('TCP' in pkt) or ('UDP' in pkt):
                    self.index.value += 1
                    flow, direction = flow_meter.process_packet(pkt)
                    flow_metrics = flow.get_data(direction)
                    #flow_metrics['Target'] = target

                    graph = Data(
                        edge_index=torch.tensor([(a, b) for (a, b, c, d) in flow_meter.flows.keys()],
                                                dtype=torch.long).t().contiguous(),
                        edge_attr=torch.tensor([float(y) for x, y in flow_metrics.items() if x not in ['src_ip', 'dst_ip']])
                    )

                    graph.num_nodes = graph.edge_index.max().item() + 1
                    graph_snapshots.append(graph)

                    print('Nodes: ', graph.num_nodes)
                    print('Edges: ', graph.num_edges)
                    print('Graph Snapshots: ', len(graph_snapshots))
                    print('\n\n')


        # Append data to final CSV file
        '''
        self.write_lock.acquire()
        self.write_data_to_csv(packet_data, self.output_file)
        self.write_lock.release()
        '''
        self.total_packets.value += counter.get_packet_count_total()
        self.in_progress.remove(file)
        self.completed.append(file)
        #self.display_progress()

        logging.info('File completed: ' + file)

        return 0

    def start_sniffer(self, file_list, parallel=False) -> list:

        if type(file_list) is str:
            results = self.run_sniffer(file_list)

        elif type(file_list) is list:

            self.file_count = len(file_list)
            if parallel:

                with ProcessPoolExecutor(max_tasks_per_child=1) as pool:
                    # Sort file_list by file size so the program processes the largest files first
                    results = pool.map(self.run_sniffer, sorted(file_list, key=lambda file: os.path.getsize(file), reverse=True))

            else:
                results = [self.run_sniffer(file) for file in file_list]

        return results

    def write_data_to_csv(self, data, output_file) -> None:

        mode = 'w' if self.index.value == 0 else 'a'

        with open(output_file, mode=mode, newline='') as csv_file:

            writer = csv.DictWriter(csv_file, fieldnames=columns.keys())
            if mode == 'w':
                writer.writeheader()

            for key, group in data.items():
                self.index.value += len(group)

                for flow in group:
                    for k in flow:
                        if type(flow[k]) not in (str, int) and flow[k] > 0:
                            flow[k] = format(flow[k], ".8f")
                    writer.writerow(flow)

    def display_progress(self) -> None:

        print('\x1b[2K\r')
        print('-------------------------------------------------------------------------------------------------')
        print('IN PROGRESS  [' + str(self.file_count - len(self.completed) - len(
            self.in_progress)) + ' files waiting to be processed]' + '\n' + str(
            [i for i in self.in_progress]) + '\n\n' + 'COMPLETED  [' + str(len(self.completed)) + '/' + str(
            self.file_count) + ']' + '\n' + str([i for i in self.completed]))
        print('-------------------------------------------------------------------------------------------------')
        time.sleep(0.25)

    def print_end_message(self, elapsed_time) -> None:

        print("Preprocessed " + str(self.index.value) + " out of " + str(
            self.total_packets.value) + " total packets in " + pretty_time_delta(elapsed_time))
        print("Program End")
