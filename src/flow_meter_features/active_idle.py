from .stats import Statistics
from src.flow_meter_features import constants


class ActiveIdle:

    def __init__(self) -> None:
        self.active = 0.0
        self.idle = 0.0
        self.start_active = 0.0
        self.last_active = 0.0
        self.active_stats = Statistics()
        self.idle_stats = Statistics()

    def update_active_idle(self, inter_arrival_time) -> None:

        if inter_arrival_time > 0:

            if inter_arrival_time > constants.CLUMP_TIMEOUT:

                if (inter_arrival_time - self.last_active) > constants.ACTIVE_TIMEOUT:
                    duration = abs(float(self.last_active - self.start_active))
                    if duration > 0:
                        self.active = 1e3 * duration
                    self.idle = 1e3 * (inter_arrival_time - self.last_active)
                    self.start_active = inter_arrival_time
                    self.last_active = inter_arrival_time
                else:
                    self.last_active = inter_arrival_time

            self.active_stats.calculate_statistics(self.active)
            self.idle_stats.calculate_statistics(self.idle)


