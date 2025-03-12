import os
import lzma
from scapy.all import *
from src.PacketCounter import PacketCounter
from src.FlowMeterMetrics import FlowMeterMetrics
from src.utils import pretty_time_delta
from src.Database import DatabaseAPI
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor
import torch
from torch_geometric.data import Data
from time import time, sleep, perf_counter
from datetime import datetime


class Sniffer:
    file_count = 0
    graph_write_file_count = 2000

    def __init__(self, output_directory) -> None:

        manager = Manager()
        self.completed = manager.list()
        self.in_progress = manager.list()

        self.total_packets = manager.Value('i', 0)
        self.index = manager.Value('i', 0)
        self.total_graph_snapshots = manager.Value('i', 0)

        self.output_directory = os.path.abspath(output_directory)
        self.display_output = ''

    def run_sniffer(self, file) -> int:

        db = DatabaseAPI('NetworkIntrusion.db')
        db.connect()

        logging.info('Parsing file: ' + file)
        self.in_progress.append(file)
        self.display_progress()

        base_filename = os.path.splitext(os.path.basename(file))[0]

        db_columns = {'graphs': 'BLOB', 'timestamp': 'REAL'}

        if db.table_exists(base_filename):
            db.execute_query(f'DELETE FROM "{base_filename}";')

            if db.table_exists('SQLITE_SEQUENCE'):
                db.execute_query(f'DELETE FROM SQLITE_SEQUENCE WHERE name="{base_filename}";')

        db.create_table(base_filename, db_columns)

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

        for pkt in PcapReader(file):

            counter.packet_count_total += 1

            if counter.packet_count_total == 0:
                start = pkt.time

            if ('IP' in pkt) or ('IPv6' in pkt):
                if ('TCP' in pkt) or ('UDP' in pkt):
                    counter.packet_count_preprocessed += 1
                    flow_meter.process_packet(pkt)

            if pkt.time - end >= time_step:
                # print(pkt.time, pkt.time - end)

                labels = [torch.ones(len(flow_meter.flows)), torch.zeros(len(flow_meter.flows))][target == 0]

                graph = Data(
                    edge_index=torch.tensor(
                        [(a, b) for (a, b, c, d) in flow_meter.flows.keys()]).t().contiguous(),
                    edge_attr=torch.tensor([flow.get_data_as_list() for flow in flow_meter.flows.values()]),
                    y=labels
                )

                graph.nodes = list(flow_meter.node_ids.keys())
                graph_snapshots.append(
                    (lzma.compress(pickle.dumps(graph)),
                     float(pkt.time)
                     ))
                graph_snapshot_count += 1

                # self.print_graph_details(graph, graph_snapshot_count)

                if len(graph_snapshots) >= self.graph_write_file_count:
                    db.insert_data(base_filename, graph_snapshots)
                    graph_snapshots = []

                # print(pkt.time, pkt.time - end)
                end = pkt.time

        if len(graph_snapshots) > 0:
            db.insert_data(base_filename, graph_snapshots)

        capture_time = datetime.fromtimestamp(float(end - start))
        # print('Capture time: ', capture_time.strftime("%M:%S"))

        self.index.value += counter.packet_count_preprocessed
        self.total_packets.value += counter.packet_count_total
        self.total_graph_snapshots.value += graph_snapshot_count
        self.in_progress.remove(file)
        self.completed.append(file)
        self.display_progress()

        logging.info('File completed: ' + file)
        db.disconnect()

        return 0

    def start_sniffer(self, file_list, parallel=False) -> list:

        if type(file_list) is str:
            self.file_count = 1
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

    @staticmethod
    def print_graph_details(graph, graph_snapshot_count) -> None:
        print('Nodes: ', graph.num_nodes)
        print('Edges: ', graph.num_edges)
        print('Graph Snapshots: ', graph_snapshot_count)
        print('\n\n')

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

        output = f"\n\nPreprocessed {self.index.value} out of {self.total_packets.value} total packets in {pretty_time_delta(elapsed_time)}\nBuilt Dataset of {self.total_graph_snapshots.value} graph snapshots\nProgram End"
        print(output)
