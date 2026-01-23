import os
import lzma
from scapy.all import *
from src.PacketCounter import PacketCounter
from src.FlowMeterMetrics import FlowMeterMetrics
from src.utils import pretty_time_delta
from src.Database import GraphDataset
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import torch
from torch_geometric.data import Data


class Sniffer:
    file_count = 0
    graph_write_file_count = 5000
    max_blob_size = 1000000000

    def __init__(self, db_name) -> None:

        manager = Manager()
        self.completed = manager.list()
        self.in_progress = manager.list()
        self.lock = manager.Lock()

        self.total_packets = manager.Value('i', 0)
        self.index = manager.Value('i', 0)
        self.total_graph_snapshots = manager.Value('i', 0)

        self.db = GraphDataset(db_name)  # DatabaseAPI(db_name)
        self.display_output = ''

    def run_sniffer(self, file) -> int:

        logging.info('Parsing file: ' + file)

        base_filename = os.path.splitext(os.path.basename(file))[0]
        conn = self.db.connect()

        target = 0

        if file.lower().__contains__('attack'):
            target = 1

        counter = PacketCounter()
        graph = Data(
            edge_index=torch.tensor([]),
            edge_attr=torch.tensor([])
        )

        graph_snapshots = []
        graph_snapshot_size = 0
        graph_snapshot_count = 0
        flow_meter = FlowMeterMetrics(output_mode="flow")

        start = 0
        end = 0
        packet_timestamp = 0
        time_steps_per_second = 5
        time_step = 1 / time_steps_per_second
        # time_step = 5
        # packet_times = []

        for pkt in PcapReader(file):

            counter.packet_count_total += 1

            if counter.packet_count_total == 0:
                start = pkt.time

            packet_timestamp = pkt.time

            if ('IP' in pkt) or ('IPv6' in pkt):
                if ('TCP' in pkt) or ('UDP' in pkt):
                    counter.packet_count_preprocessed += 1
                    flow_meter.process_packet(pkt)

            if packet_timestamp - end >= time_step:

                graph.edge_index = torch.tensor([(a, b) for (a, b, c, d) in flow_meter.flows.keys()]).t().contiguous()
                graph.edge_attr = torch.tensor(flow_meter.get_flows_as_list(pkt.time - time_step, pkt.time))
                graph.y = [torch.ones(len(flow_meter.flows)), torch.zeros(len(flow_meter.flows))][target == 0]

                graph.nodes = list(flow_meter.node_ids.keys())
                graph.num_nodes = len(graph.nodes)         # PyG Transforms need this graph attribute listed as num_nodes
                graph.timestamp = packet_timestamp

                graph_snapshots.append(graph)
                graph_snapshot_count += 1
                # self.print_graph_details(graph, graph_snapshot_count)
                #if len(graph_snapshots) >= self.graph_write_file_count:

                if graph_snapshot_count % 5000 == 0:
                    graph_snapshot_size = self.db.estimate_compressed_size(graph_snapshots)
                   #print(graph_snapshot_size, self.max_blob_size)

                if graph_snapshot_size >= (self.max_blob_size - 100000):
                    with self.lock:
                        # self.db.extend(graph_snapshots)

                        conn.insert_binary_data(
                            self.db.db_table_name,
                            self.db.db_columns,
                            GraphDataset.serialize(
                                graph_snapshots,
                                graph_snapshot_count,
                                packet_timestamp,
                                base_filename
                            )
                        )
                    graph_snapshots = []

                end = packet_timestamp

        if len(graph_snapshots) > 0:
            with self.lock:
                # self.db.extend(graph_snapshots)
                conn.insert_binary_data(
                    self.db.db_table_name,
                    self.db.db_columns,
                    GraphDataset.serialize(
                        graph_snapshots,
                        graph_snapshot_count,
                        packet_timestamp,
                        base_filename
                    )
                )

        self.index.value += counter.packet_count_preprocessed
        self.total_packets.value += counter.packet_count_total
        self.total_graph_snapshots.value += graph_snapshot_count

        return file

    def start_sniffer(self, file_list, parallel=False) -> list:

        results = []

        if type(file_list) is str:
            self.file_count = 1
            results = self.run_sniffer(file_list)

        elif type(file_list) is list:

            self.file_count = len(file_list)
            if parallel:

                futures = []

                with ProcessPoolExecutor(max_tasks_per_child=1) as pool:
                    #results = pool.map(self.run_sniffer, file_list)
                    for i in file_list:

                        logging.info('Parsing file: ' + i)

                        self.in_progress.append(i)
                        self.display_progress()
                        futures.append(pool.submit(self.run_sniffer, i))

                    for future in as_completed(futures):

                        file = future.result()
                        self.in_progress.remove(str(file))
                        self.completed.append(str(file))
                        self.display_progress()
                        results.append(str(file))

                        logging.info('File completed: ' + file)

            else:
                results = [self.run_sniffer(file) for file in file_list]

        self.db.reorder_table_final()
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
