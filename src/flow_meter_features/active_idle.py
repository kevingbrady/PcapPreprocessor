from .stats import Statistics
from src.flow_meter_features import constants


class ActiveIdle:

    def __init__(self):
        self.last_timestamp = 0
        self.active = 0.0
        self.idle = 0.0
        self.start_active = 0
        self.last_active = 0
        self.active_stats = Statistics()
        self.idle_stats = Statistics()

    def process_packet(self, packet, direction):

        timeout = packet.time - self.last_timestamp
        if timeout > constants.CLUMP_TIMEOUT:
            self.update_active_idle(packet.time)

        self.active_stats.calculate_statistics(self.active, None)
        self.idle_stats.calculate_statistics(self.idle, None)
        #self.last_timestamp = packet.time

    def update_active_idle(self, current_time):
        """Adds a packet to the current list of packets.

        Args:
            packet: Packet to be update active time

        """
        if (current_time - self.last_active) > constants.ACTIVE_TIMEOUT:
            duration = abs(float(self.last_active - self.start_active))
            if duration > 0:
                self.active = 1e6 * duration
            self.idle = 1e6 * (current_time - self.last_active) if self.last_active > 0 else 0
            self.start_active = current_time
            self.last_active = current_time
        else:
            self.last_active = current_time