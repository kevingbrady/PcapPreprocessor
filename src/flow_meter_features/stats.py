import math
from src.flow_meter_features.context.packet_direction import PacketDirection


class Statistics:

    def __init__(self):
        self.data = {
            None: {
                'count': 0,
                'M': 0.0,
                'S': 0.0,
                'sum': 0,
                'max': 0,
                'min': 0
            },
            PacketDirection.FORWARD: {
                'count': 0,
                'M': 0.0,
                'S': 0.0,
                'sum': 0,
                'max': 0,
                'min': 0
            },
            PacketDirection.REVERSE: {
                'count': 0,
                'M': 0.0,
                'S': 0.0,
                'sum': 0,
                'max': 0,
                'min': 0
            }
        }

    def calculate_statistics(self, value, direction):

        self._calculate_max_min(value, None)
        self._calculate_max_min(value, direction)
        self._calculate_statistics(value, None)
        self._calculate_statistics(value, direction)

    def get_avg(self, direction=None):
        return self.data[direction]['sum'] / self.data[direction]['count'] if self.data[direction]['count'] > 0 else 0.0

    def get_sum(self, direction=None):
        return self.data[direction]['sum']

    def get_max(self, direction=None):
        return self.data[direction]['max']

    def get_min(self, direction=None):
        return self.data[direction]['min']

    def get_mean(self, direction=None):

        return self.data[direction]['M'] if self.data[direction]['count'] > 0 else 0.0

    def get_variance(self, direction=None):

        return self.data[direction]['S'] / (self.data[direction]['count'] - 1) if self.data[direction][
                                                                                      'count'] > 1 else 0.0

    def get_standard_deviation(self, direction=None):

        return math.sqrt(self.get_variance(direction))

    def _calculate_max_min(self, value, direction):

        if value > 0:
            self.data[direction]['sum'] += value
            self.data[direction]['max'] = max(value, self.data[direction]['max'])
            self.data[direction]['min'] = value if self.data[direction]['min'] == 0 else min(value,
                                                                                             self.data[direction][
                                                                                                 'min'])

    def _calculate_statistics(self, value, direction):

        if self.data[direction]['count'] > 1:
            oldM = self.data[direction]['M']
            oldS = self.data[direction]['S']
            self.data[direction]['M'] = (oldM + (value - oldM)) / self.data[direction]['count']
            self.data[direction]['S'] = oldS + (value - oldM) * (value - self.data[direction]['M'])
