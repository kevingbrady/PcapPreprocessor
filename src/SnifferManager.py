from multiprocessing.managers import BaseManager
from multiprocessing import Lock, Value
from src.FlowMeterMetrics import FlowMeterMetrics
import pandas as pd


class SnifferManager(BaseManager):

    def __init__(self):
        SnifferManager.register('FlowMeterMetrics', FlowMeterMetrics)

        self.total_packets = Value('i', 0)
        self.completed = []
        self.in_progress = []
        self.columns = []
        self.index = Value('i', 0)
        self.start_time = Value('i', 0)

        super().__init__()
        self.start()

    def write_data_to_csv(self, data, output_file):

        header = True if self.index.value == 0 else False
        mode = 'w' if self.index.value == 0 else 'a'

        new_frame = pd.DataFrame(data, columns=self.columns)
        new_frame.index += self.index.value
        new_frame.to_csv(output_file, mode=mode, header=header, index_label='No')
        self.index.value += len(data)

    def shutdown(self):
        self.shutdown()
