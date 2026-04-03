from scapy.all import *
from sympy.vector import parametric_region_list

from src.PacketCounter import PacketCounter
from src.FlowMeterMetrics import FlowMeterMetrics
from src.utils import pretty_time_delta
from src.Database import GraphDataset
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor, as_completed
import torch
import numpy as np
from torch_geometric.data import Data


class Sniffer:
    file_count = 0
    graph_write_file_count = 5000

    # max_blob_size = 1000000000

    def __init__(self, db_name: str) -> None:

        manager = Manager()
        self.completed = manager.list()
        self.in_progress = manager.list()
        self.lock = manager.Lock()

        self.total_packets = manager.Value('i', 0)
        self.index = manager.Value('i', 0)
        self.total_graph_snapshots = manager.Value('i', 0)

        self.db = GraphDataset(db_name)  # DatabaseAPI(db_name)
        self.display_output = ''

    def run_sniffer(self, file: str) -> str:

        logging.info('Parsing file: ' + file)

        base_filename = os.path.splitext(os.path.basename(file))[0]
        conn = self.db.connect()

        target = 0

        if file.lower().__contains__('attack'):
            target = 1

        counter = PacketCounter()

        graph_snapshots = []
        graph_snapshot_count = 0
        graph_snapshot_size = 0
        flow_meter = FlowMeterMetrics(output_mode="flow")

        last_packet_timestamp = 0
        time_steps_per_second = 5
        time_step = 1 / time_steps_per_second

        for pkt in PcapReader(file):

            counter.packet_count_total += 1

            if ('IP' in pkt) or ('IPv6' in pkt):
                if ('TCP' in pkt) or ('UDP' in pkt):
                    counter.packet_count_preprocessed += 1
                    flow_meter.process_packet(pkt)

            if pkt.time - last_packet_timestamp >= time_step:

                flows = flow_meter.get_flows_as_list(pkt.time, time_step)
                node_ids = list(flow_meter.node_ids.keys())

                num_nodes = len(node_ids)
                num_edges = len(flows)


                flow_edge_list = [(flow_key.source[0], flow_key.destination[0]) for flow_key in flow_meter.flows.keys()]

                graph = Data(
                    x=torch.ones(num_nodes, 1),
                    edge_index=torch.empty(2, 0, dtype=torch.long) if not flow_edge_list
                        else torch.tensor(flow_edge_list, dtype=torch.long).t().contiguous(),
                    edge_attr=torch.tensor(flows),
                    y=[torch.ones(num_edges, 1), torch.zeros(num_edges, 1)][target == 0],
                    node_ids=node_ids,
                    num_nodes=num_nodes,
                    num_edges=num_edges,
                    t=float(pkt.time)
                )

                graph_snapshots.append(GraphDataset.serialize(graph, base_filename))
                graph_snapshot_count += 1

                last_packet_timestamp = pkt.time

                '''if len(graph_snapshots) >= self.graph_write_file_count:
                    with self.lock:
                        conn.insert_data_list(self.db.db_table_name, self.db.db_columns, graph_snapshots)

                    graph_snapshots = []'''
        '''
        if len(graph_snapshots) > 0:
            with self.lock:
                conn.insert_data_list(self.db.db_table_name, self.db.db_columns, graph_snapshots)'''

        self.index.value += counter.packet_count_preprocessed
        self.total_packets.value += counter.packet_count_total
        self.total_graph_snapshots.value += graph_snapshot_count

        return file

    def start_sniffer(self, file_list: list[str], display_progress: bool = True, parallel: bool = False) -> list:

        if type(file_list) == str:
            file_list = [file_list]

        results = []
        futures = []
        self.file_count = len(file_list)

        if parallel:
            pool = ProcessPoolExecutor(max_tasks_per_child=1)

        for i in file_list:

            logging.info('Parsing file: ' + i)
            self.in_progress.append(i)

            if display_progress:
                self.display_progress()

            if parallel:
                futures.append(pool.submit(self.run_sniffer, i))

            else:
                self.run_sniffer(i)
                self.in_progress.remove(i)
                self.completed.append(i)
                results.append(i)

                if display_progress:
                    self.display_progress()

                logging.info('File completed: ' + results[-1])

        if parallel:
            for future in futures:
                file = future.result()
                self.in_progress.remove(file)
                self.completed.append(file)
                results.append(file)

                if display_progress:
                    self.display_progress()

            logging.info('File completed: ' + results[-1])

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
