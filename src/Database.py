from decimal import Decimal

from src.DatabaseConnection import DatabaseConnection
from torch_geometric.data import Data
from src.utils import generate_unique_integers
from torch_geometric.data.data import BaseData
from typing import Any

import lzma
import zlib
import pickle
import os
import sys


class GraphDataset:
    def __init__(self, db_name):
        self.db_name = db_name
        self.db_full_path = './' + self.db_name + '/processed/'
        self.db_table_name = 'GraphDataset'
        self.db_columns = {
            'graph': 'BLOB',
            'nodes': 'INT',
            'edges': 'INT',
            'timestamp': 'REAL',
            'filename': 'TEXT'
        }

        os.makedirs(self.db_full_path, exist_ok=True)

        conn = self.connect()
        conn.delete_table(self.db_table_name)
        conn.create_table(self.db_table_name, self.db_columns)

    @staticmethod
    def serialize(graph: Data, filename: str) -> tuple[Any, int, int, float, str]:
        serialized_graph = lzma.compress(pickle.dumps(graph))
        return serialized_graph, graph.num_nodes, graph.num_edges, graph.timestamp, filename


    @staticmethod
    def deserialize(row: tuple[Any, int, int, float, str]) -> Any:

            return pickle.loads(lzma.decompress(row[0]))


    '''
    @staticmethod
    def serialize(graph_list: list, graph_count: int, filename: str) -> {Any, int, str}:
        serialized_graph_list = lzma.compress(pickle.dumps(graph_list))
        return {
            'serialized_graph_list': serialized_graph_list,
            'graph_count': graph_count,
            'filename': filename
        }

    @staticmethod
    def deserialize(row: (Any, int, str)) -> {list, int, str}:
        return {
            'graph_list': pickle.loads(lzma.decompress(row[0])),
            'graph_count': int(row[1]),
            'filename': row[2]
        }
        
    '''

    def estimate_compressed_size(self, graph_snapshots):
        if len(graph_snapshots) < 100:
            return

        N = 80
        sample = [graph_snapshots[i] for i in generate_unique_integers(N)]
        # uncompressed_size = sys.getsizeof(graph_snapshots)

        sample = lzma.compress(pickle.dumps(sample))
        estimated_compressed_size = (sys.getsizeof(sample) / N) * len(graph_snapshots)

        return estimated_compressed_size

    def connect(self) -> DatabaseConnection:
        return DatabaseConnection(self.db_full_path + 'sqlite.db')
