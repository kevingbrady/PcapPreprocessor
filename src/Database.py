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
        self.db_table_name = 'GraphDataset_unordered'
        self.db_columns = {
            'serialized_graph_list': 'BLOB',
            'graph_count': 'INT',
            'timestamp': 'FLOAT',
            'filename': 'TEXT'
        }

        os.makedirs(self.db_full_path, exist_ok=True)

        conn = self.connect()
        conn.delete_table(self.db_table_name)
        conn.delete_table(self.db_table_name.replace('_unordered', ''))
        conn.create_table(self.db_table_name, self.db_columns)

    def reorder_table_final(self):
        conn = self.connect()
        table_name = self.db_table_name.replace('_unordered', '')

        conn.create_table(table_name, self.db_columns)

        columns = ", ".join([f"{name}" for name in self.db_columns.keys()])
        query = f'INSERT INTO {table_name} SELECT {columns} FROM {self.db_table_name} ORDER BY timestamp, filename;'
        conn.execute_query(query)
        conn.delete_table(self.db_table_name)

    @staticmethod
    def serialize(graph_list: list, graph_count: int, timestamp: float, filename: str) -> {Any, float, str}:
        serialized_graph_list = lzma.compress(pickle.dumps(graph_list))
        return {
            'serialized_graph_list': serialized_graph_list,
            'graph_count': graph_count,
            'timestamp': float(timestamp),
            'filename': filename
        }

    @staticmethod
    def deserialize(data: [Any, int, float, str]) -> [list, int, float, str]:
        return {
            'graph_list': pickle.loads(lzma.decompress(data['graph'])),
            'graph_count': int(data['graph_count']),
            'timestamp': float(data['timestamp']),
            'filename': str(data['filename'])
        }

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
