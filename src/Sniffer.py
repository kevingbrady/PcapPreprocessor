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
from time import time, perf_counter
from datetime import datetime


class Sniffer:
    file_count = 0
    file_sizes = []
    graph_write_file_count = 500

    def __init__(self, output_file):

        manager = Manager()
        self.completed = manager.list()
        self.in_progress = manager.list()

        self.total_packets = manager.Value('i', 0)
        self.index = manager.Value('i', 0)

        self.write_lock = manager.Lock()
        self.output_file = output_file

    def packet_generator(self, file):

        generator = enumerate(PcapReader(file))

        for idx, pkt in generator:
            yield idx, pkt

    def run_sniffer(self, file) -> int:

        logging.info('Parsing file: ' + file)
        self.in_progress.append(file)
        #self.display_progress()

        target = 0

        if file.lower().__contains__('attack'):
            target = 1

        counter = PacketCounter()
        graph_snapshots = []
        graph_snapshot_count = 0
        flow_meter = FlowMeterMetrics(output_mode="flow")

        start = 0
        end = 0
        time_step_per_second = 10
        time_step = 1 / time_step_per_second

        for idx, pkt in self.packet_generator(file):

            counter.packet_count_total = idx + 1

            if idx == 0:
                start = pkt.time

            if ('IP' in pkt) or ('IPv6' in pkt):
                if ('TCP' in pkt) or ('UDP' in pkt):
                    self.index.value += 1
                    flow_meter.process_packet(pkt)

                    if pkt.time - end >= time_step:
                        #print(packet_time, packet_time - elapsed)

                        labels = [torch.ones(len(flow_meter.flows)), torch.zeros(len(flow_meter.flows))][target == 0]
                                    
                        graph = Data(
                            edge_index=torch.tensor([(a, b) for (a, b, c, d) in flow_meter.flows.keys()]).t().contiguous(),
                            edge_attr=torch.tensor([flow.get_data_as_list() for flow in flow_meter.flows.values()]),
                            y=labels
                        )

                        graph.nodes = list(flow_meter.node_ids.keys())
                        graph_snapshots.append(graph)
                        graph_snapshot_count += 1
                        end = pkt.time

                        self.print_graph_details(graph, graph_snapshot_count)

                        if graph_snapshot_count % self.graph_write_file_count == 0:
                            graph_snapshots = self.write_data_to_file(graph_snapshots, graph_snapshot_count)




        # Append data to final CSV file
        capture_time = datetime.fromtimestamp(float(end - start))
        print('Capture time: ', capture_time.strftime("%M:%S"))

        if len(graph_snapshots) > 0:
            #self.print_graph_details(graph_snapshots[-1], graph_snapshot_count)
            self.write_data_to_file(graph_snapshots, graph_snapshot_count)

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
                    results = pool.map(self.run_sniffer, file_list)

            else:
                results = [self.run_sniffer(file) for file in file_list]

        return results

    def write_data_to_file(self, graph_list, graph_total_count) -> list:

        op = ['wb', 'ab'][graph_total_count == self.graph_write_file_count]
        with open(self.output_file, op) as f:
            pickle.dump(graph_list, f)

        return []

    def print_graph_details(self, graph, graph_snapshot_count):
        print('Nodes: ', graph.num_nodes)
        print('Edges: ', graph.num_edges)
        print('Graph Snapshots: ', graph_snapshot_count)
        print('\n\n')

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
