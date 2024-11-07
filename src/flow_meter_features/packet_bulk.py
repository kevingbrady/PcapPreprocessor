from src.flow_meter_features import constants
from src.flow_meter_features.packet_count import PacketCount
from src.flow_meter_features.context.packet_direction import PacketDirection


class BulkPacketData:

    def __init__(self):

        self.forward_bulk_last_timestamp = 0
        self.forward_bulk_start_tmp = 0
        self.forward_bulk_count = 0
        self.forward_bulk_count_tmp = 0
        self.forward_bulk_duration = 0
        self.forward_bulk_packet_count = 0
        self.forward_bulk_size = 0
        self.forward_bulk_size_tmp = 0
        self.backward_bulk_last_timestamp = 0
        self.backward_bulk_start_tmp = 0
        self.backward_bulk_count = 0
        self.backward_bulk_count_tmp = 0
        self.backward_bulk_duration = 0
        self.backward_bulk_packet_count = 0
        self.backward_bulk_size = 0
        self.backward_bulk_size_tmp = 0

    def update_flow_bulk(self, packet, direction) -> None:
        """Update bulk flow

        Args:
            packet: Packet to be parsed as bulk
            direction: Packet Direction enum
        """

        payload = PacketCount.get_payload(packet)
        payload_size = len(payload) if payload != 0 else 0

        if payload_size == 0:
            return
        if direction == PacketDirection.FORWARD:

            if self.backward_bulk_last_timestamp > self.forward_bulk_start_tmp:
                self.forward_bulk_start_tmp = 0
            if self.forward_bulk_start_tmp == 0:
                self.forward_bulk_start_tmp = packet.time
                self.forward_bulk_last_timestamp = packet.time
                self.forward_bulk_count_tmp = 1
                self.forward_bulk_size_tmp = payload_size
            else:

                if (packet.time - self.forward_bulk_last_timestamp) > constants.CLUMP_TIMEOUT:
                    self.forward_bulk_start_tmp = packet.time
                    self.forward_bulk_last_timestamp = packet.time
                    self.forward_bulk_count_tmp = 1
                    self.forward_bulk_size_tmp = payload_size
                else:  # Add to bulk
                    self.forward_bulk_count_tmp += 1
                    self.forward_bulk_size_tmp += payload_size
                    if self.forward_bulk_count_tmp == constants.BULK_BOUND:
                        self.forward_bulk_count += 1
                        self.forward_bulk_packet_count += self.forward_bulk_count_tmp
                        self.forward_bulk_size += self.forward_bulk_size_tmp
                        self.forward_bulk_duration += (packet.time - self.forward_bulk_start_tmp)
                    elif self.forward_bulk_count_tmp > constants.BULK_BOUND:
                        self.forward_bulk_packet_count += 1
                        self.forward_bulk_size += payload_size
                        self.forward_bulk_duration += (packet.time - self.forward_bulk_last_timestamp)
                    self.forward_bulk_last_timestamp = packet.time
        else:

            if self.forward_bulk_last_timestamp > self.backward_bulk_start_tmp:
                self.backward_bulk_start_tmp = 0
            if self.backward_bulk_start_tmp == 0:
                self.backward_bulk_start_tmp = packet.time
                self.backward_bulk_last_timestamp = packet.time
                self.backward_bulk_count_tmp = 1
                self.backward_bulk_size_tmp = payload_size
            else:
                if (packet.time - self.backward_bulk_last_timestamp) > constants.CLUMP_TIMEOUT:
                    self.backward_bulk_start_tmp = packet.time
                    self.backward_bulk_last_timestamp = packet.time
                    self.backward_bulk_count_tmp = 1
                    self.backward_bulk_size_tmp = payload_size
                else:  # Add to bulk
                    self.backward_bulk_count_tmp += 1
                    self.backward_bulk_size_tmp += payload_size
                    if self.backward_bulk_count_tmp == constants.BULK_BOUND:
                        self.backward_bulk_count += 1
                        self.backward_bulk_packet_count += self.backward_bulk_count_tmp
                        self.backward_bulk_size += self.backward_bulk_size_tmp
                        self.backward_bulk_duration += (packet.time - self.backward_bulk_start_tmp)
                    elif self.backward_bulk_count_tmp > constants.BULK_BOUND:
                        self.backward_bulk_packet_count += 1
                        self.backward_bulk_size += payload_size
                        self.backward_bulk_duration += (packet.time - self.backward_bulk_last_timestamp)
                    self.backward_bulk_last_timestamp = packet.time
                    
    def get_bytes_per_bulk(self, direction) -> float:
        if direction == PacketDirection.FORWARD:
            if self.forward_bulk_count > 0:
                return self.forward_bulk_size / self.forward_bulk_count

        else:
            if self.backward_bulk_count > 0:
                return self.backward_bulk_size / self.backward_bulk_count
        return 0.0

    def get_packets_per_bulk(self, direction) -> float:
        if direction == PacketDirection.FORWARD:
            if self.forward_bulk_count > 0:
                return self.forward_bulk_packet_count / self.forward_bulk_count

        else:
            if self.backward_bulk_count > 0:
                return self.backward_bulk_packet_count / self.backward_bulk_count

        return 0.0

    def get_bulk_rate(self, direction) -> float:
        if direction == PacketDirection.FORWARD:
            if self.forward_bulk_duration > 0:
                return self.forward_bulk_size / self.forward_bulk_duration

        else:
            if self.backward_bulk_duration > 0:
                return self.backward_bulk_size / self.backward_bulk_duration
        return 0.0
