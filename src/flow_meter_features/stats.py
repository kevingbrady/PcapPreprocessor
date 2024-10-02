import math
from src.flow_meter_features.context.packet_direction import PacketDirection


class Statistics:
    '''
    Use Welford's algorithm to calculate moving mean and variance to keep statistics info for all flow metrics
    '''
    def __init__(self):
        self.data = {
            None: {
                'count': 0,
                'mean': 0.0,
                'variance': 0.0,
                'sum': 0,
                'max': 0,
                'min': 0
            },
            PacketDirection.FORWARD: {
                'count': 0,
                'mean': 0.0,
                'variance': 0.0,
                'sum': 0,
                'max': 0,
                'min': 0
            },
            PacketDirection.REVERSE: {
                'count': 0,
                'mean': 0.0,
                'variance': 0.0,
                'sum': 0,
                'max': 0,
                'min': 0
            }
        }

    def calculate_statistics(self, value, direction=None):

        if direction is not None:
            self.data[direction]['count'] += 1

        self.data[None]['count'] += 1
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

        return self.data[direction]['mean'] if self.data[direction]['count'] > 0 else 0.0

    def get_variance(self, direction=None):

        return self.data[direction]['variance'] if self.data[direction]['count'] > 0 else 0.0

    def get_standard_deviation(self, direction=None):

        if self.data[direction]['count'] <= 1:
            return 0
        return math.sqrt(self.get_variance(direction) / (self.data[direction]['count'] - 1))

    def _calculate_max_min(self, value, direction):

        self.data[direction]['sum'] += value
        self.data[direction]['max'] = max([value, self.data[direction]['max']]) if self.data[direction]['max'] != 0 else value
        self.data[direction]['min'] = min([value, self.data[direction]['min']]) if self.data[direction]['min'] != 0 else value

    def _calculate_statistics(self, value, direction):

        if self.data[direction]['count'] >= 1:
            #oldM = self.data[direction]['M']
            #oldS = self.data[direction]['S']
            #self.data[direction]['M'] = (oldM + (value - oldM)) / self.data[direction]['count']
            #self.data[direction]['S'] = oldS + (value - oldM) * (value - self.data[direction]['M'])
            new_mean = self.data[direction]['mean'] + (value - self.data[direction]['mean']) * 1./self.data[direction]['count']
            new_variance = self.data[direction]['variance'] + (value - self.data[direction]['mean']) * (value - new_mean)

            self.data[direction]['mean'] = new_mean
            self.data[direction]['variance'] = new_variance


