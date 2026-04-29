import math
from src.flow_meter_features.context.packet_direction import PacketDirection
from typing import Any


class Statistics:
    '''
    Use Welford's algorithm to calculate moving mean and variance to keep statistics info for all flow metrics
    '''
    def __init__(self) -> None:
        self.data =  {
                'count': 0,
                'mean': 0.0,
                'variance': 0.0,
                'sum': 0,
                'max': 0,
                'min': 0
            }

    def calculate_statistics(self, value) -> None:

        self.data['count'] += 1
        self._calculate_max_min(value)
        self._calculate_statistics(value)

    def get_avg(self) -> float:
        return self.data['sum'] / self.data['count'] if self.data['count'] > 0 else 0.0

    def get_sum(self) -> Any:
        return self.data['sum']

    def get_max(self) -> Any:
        return self.data['max']

    def get_min(self) -> Any:
        return self.data['min']

    def get_mean(self) -> float:

        return self.data['mean'] if self.data['count'] > 0 else 0.0

    def get_variance(self) -> float:

        return self.data['variance'] if self.data['count'] > 0 else 0.0

    def get_standard_deviation(self) -> float:

        return math.sqrt(self.get_variance() / (self.data['count'] - 1)) if self.data['count'] > 1 else 0.0

    def _calculate_max_min(self, value) -> None:

        self.data['sum'] += value
        self.data['max'] = max([value, self.data['max']]) if self.data['max'] != 0 else value
        self.data['min'] = min([value, self.data['min']]) if self.data['min'] != 0 else value

    def _calculate_statistics(self, value) -> None:

        if self.data['count'] >= 1:

            new_mean = self.data['mean'] + (value - self.data['mean']) * 1./self.data['count']
            new_variance = self.data['variance'] + (value - self.data['mean']) * (value - new_mean)

            self.data['mean'] = new_mean
            self.data['variance'] = new_variance


