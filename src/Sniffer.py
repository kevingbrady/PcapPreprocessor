from scapy.all import *

from src.PacketCounter import PacketCounter
from src.ConnectionMeterMetrics import ConnectionMeterMetrics
from src.utils import pretty_time_delta
from src.Database import GraphDataset
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor, as_completed
import torch
import numpy as np
import shutil
from torch_geometric.data import Data, TemporalData


class Sniffer:

    file_count = 0
    graph_write_file_count = 25000

    def __init__(self, db_name: str) -> None:

        manager = Manager()
        self.completed = manager.list()
        self.in_progress = manager.list()

        self.total_packets = manager.Value('i', 0)
        self.index = manager.Value('i', 0)
        self.total_graph_snapshots = manager.Value('i', 0)

        self.db = GraphDataset(db_name)  # DatabaseAPI(db_name)
        self.display_output = ''

    def run_sniffer(self, file: str, write_to_db: bool=False) -> str:

        logging.info('Parsing file: ' + file)

        base_filename = os.path.splitext(os.path.basename(file))[0]
        conn = self.db.connect()

        target = 0

        if file.lower().__contains__('attack'):
            target = 1

        counter = PacketCounter()

        graph_snapshots = []
        graph_snapshot_count = 0
        connection_tracker = ConnectionMeterMetrics()

        last_graph_timestamp = 0
        time_steps_per_second = 5
        time_step = 1 / time_steps_per_second

        for pkt in PcapReader(file):

            counter.packet_count_total += 1
            if last_graph_timestamp == 0.0:
                last_graph_timestamp = pkt.time

            if ('IP' in pkt) or ('IPv6' in pkt):
                if ('TCP' in pkt) or ('UDP' in pkt):

                    counter.packet_count_preprocessed += 1
                    connection_tracker.process_packet(pkt, filter=True)

            if pkt.time - last_graph_timestamp >= time_step:

                nodes, node_features, connections, connection_edge_list = connection_tracker.get_graph_data(pkt.time - time_step, pkt.time, sparse=True)
                num_nodes = len(nodes)
                num_edges = len(connections)

                graph = Data(
                    x=node_features,
                    edge_index=connection_edge_list,
                    edge_attr=connections,
                    y=[torch.ones(num_edges, 1), torch.zeros(num_edges, 1)][target == 0],
                    node_ids=nodes,
                    num_nodes=num_nodes,
                    num_edges=num_edges,
                    t=float(pkt.time)
                )

                '''
                graph = TemporalData(
                    src=connection_edge_list[0],
                    dst=connection_edge_list[1],
                    t=torch.tensor([pkt.time], dtype=torch.float),
                    msg=connections,
                    y=[torch.ones(num_edges, 1), torch.zeros(num_edges, 1)][target == 0],
                    num_nodes=num_nodes,
                    num_edges=num_edges
                )
                '''
                graph_snapshots.append(GraphDataset.serialize(graph, float(pkt.time), base_filename))
                graph_snapshot_count += 1

                last_graph_timestamp = pkt.time

            if write_to_db:
                if len(graph_snapshots) % self.graph_write_file_count == 0:
                    conn.insert_data_list(self.db.db_table_name, self.db.db_columns, graph_snapshots)
                    graph_snapshots = []


        if write_to_db:
            if len(graph_snapshots) > 0:
                conn.insert_data_list(self.db.db_table_name, self.db.db_columns, graph_snapshots)

        self.index.value += counter.packet_count_preprocessed
        self.total_packets.value += counter.packet_count_total
        self.total_graph_snapshots.value += graph_snapshot_count

        return file

    def start_sniffer(self, file_list: list[str], write_to_db: bool=False, display_progress: bool = True, parallel: bool = False) -> None:

        if type(file_list) == str:
            file_list = [file_list]

        futures = []
        self.file_count = len(file_list)
        num_workers = (1, os.cpu_count())[parallel]
        pool = ProcessPoolExecutor(max_tasks_per_child=1, max_workers=num_workers)

        for i in file_list:

            logging.info('Parsing file: ' + i)
            self.in_progress.append(i)

            if display_progress: self.display_progress()

            futures.append(pool.submit(self.run_sniffer, i, write_to_db))

        for future in as_completed(futures):
            file = future.result()
            self.in_progress.remove(file)
            self.completed.append(file)

            if display_progress: self.display_progress()

            logging.info('File completed: ' + file)

        self.reorder_data_table_final()

    def reorder_data_table_final(self):
        conn = self.db.connect()
        conn.execute_query(f'CREATE TABLE {self.db.db_table_name}_reorder AS SELECT * FROM {self.db.db_table_name} ORDER BY filename ASC, timestamp ASC')
        conn.execute_query(f'DROP TABLE {self.db.db_table_name}')
        conn.execute_query(f'ALTER TABLE {self.db.db_table_name}_reorder RENAME TO {self.db.db_table_name}')
        conn.execute_query(f'CREATE INDEX timestamp_index ON {self.db.db_table_name} (timestamp)')
        conn.execute_query(f'CREATE INDEX filename_index ON {self.db.db_table_name} (filename)')


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
