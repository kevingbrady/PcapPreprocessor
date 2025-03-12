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

    def process_packet(self, packet, last_timestamp, direction) -> None:

        if last_timestamp > 0:

            timeout = packet.time - last_timestamp

            if timeout > constants.CLUMP_TIMEOUT:

                if (timeout - self.last_active) > constants.ACTIVE_TIMEOUT:
                    duration = abs(float(self.last_active - self.start_active))
                    if duration > 0:
                        self.active = 1e3 * duration
                    self.idle = 1e3 * (timeout - self.last_active)
                    self.start_active = timeout
                    self.last_active = timeout
                else:
                    self.last_active = timeout

            self.active_stats.calculate_statistics(self.active, direction)
            self.idle_stats.calculate_statistics(self.idle, direction)
