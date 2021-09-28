from scapy.layers.inet import IP, TCP
from src.flow_meter_features.context.packet_direction import PacketDirection


class FlowBytes:
    """Extracts features from the traffic related to the bytes in a flow"""

    def __init__(self, feature):

        self.byte_data = {
            None: {
                'total_bytes': 0,
                'header_size_sum': 0,
                'header_size_min': 0,
                'header_size_max': 0
            },
            PacketDirection.FORWARD: {
                'total_bytes': 0,
                'header_size_sum': 0,
                'header_size_min': 0,
                'header_size_max': 0
            },
            PacketDirection.REVERSE: {
                'total_bytes': 0,
                'header_size_sum': 0,
                'header_size_min': 0,
                'header_size_max': 0
            }
        }

        self.duration = 0
        self.feature = feature

    def process_packet(self, packet, direction):

        self.byte_data[None]['total_bytes'] += len(packet)
        self.byte_data[direction]['total_bytes'] += len(packet)

        self.byte_data[None]['header_size_sum'] += self._header_size(packet)
        self.byte_data[direction]['header_size_sum'] += self._header_size(packet)

        self.byte_data[None]['header_size_min'] = min(self.byte_data[None]['header_size_min'],
                                                      self._header_size(packet))
        self.byte_data[direction]['header_size_min'] = min(self.byte_data[direction]['header_size_min'],
                                                           self._header_size(packet))

        self.byte_data[None]['header_size_max'] = max(self.byte_data[None]['header_size_max'],
                                                      self._header_size(packet))
        self.byte_data[direction]['header_size_max'] = max(self.byte_data[direction]['header_size_max'],
                                                           self._header_size(packet))

    @staticmethod
    def _header_size(packet):
        return packet[IP].ihl * 4 if TCP in packet else 8

    def get_bytes(self, direction=None) -> int:
        """Calculates the amount bytes being transfered.

        Returns:
            int: The amount of bytes.

        """
        return self.byte_data[direction]['total_bytes']

    def get_rate(self) -> float:
        """Calculates the rate of the bytes being transfered in the current flow.

        Returns:
            float: The bytes/sec sent.

        """

        if self.duration == 0:
            rate = 0
        else:
            rate = self.get_bytes() / self.duration

        return rate

    def get_bytes_sent(self) -> int:
        """Calculates the amount bytes sent from the machine being used to run DoHlyzer.

        Returns:
            int: The amount of bytes.

        """
        return self.get_bytes(PacketDirection.FORWARD)

    def get_sent_rate(self) -> float:
        """Calculates the rate of the bytes being sent in the current flow.

        Returns:
            float: The bytes/sec sent.

        """
        sent = self.get_bytes_sent()

        if self.duration == 0:
            rate = -1
        else:
            rate = sent / self.duration

        return rate

    def get_bytes_received(self) -> int:
        """Calculates the amount bytes received.

        Returns:
            int: The amount of bytes.

        """
        return self.get_bytes(PacketDirection.REVERSE)

    def get_received_rate(self) -> float:
        """Calculates the rate of the bytes being received in the current flow.

        Returns:
            float: The bytes/sec received.

        """
        received = self.get_bytes_received()

        if self.duration == 0:
            rate = -1
        else:
            rate = received / self.duration

        return rate

    def get_forward_header_bytes(self) -> int:
        """Calculates the amount of header bytes in the header sent in the same direction as the flow.

        Returns:
            int: The amount of bytes.

        """

        return self.byte_data[PacketDirection.FORWARD]['header_size_sum']

    def get_forward_rate(self) -> int:
        """Calculates the rate of the bytes being going forward
        in the current flow.

        Returns:
            float: The bytes/sec forward.

        """
        forward = self.get_forward_header_bytes()

        if self.duration > 0:
            rate = forward / self.duration
        else:
            rate = -1

        return rate

    def get_reverse_header_bytes(self) -> int:
        """Calculates the amount of header bytes in the header sent in the opposite direction as the flow.

        Returns:
            int: The amount of bytes.

        """

        return self.byte_data[PacketDirection.REVERSE]['header_size_sum']

    def get_min_forward_header_bytes(self) -> int:
        """Calculates the amount of header bytes in the header sent in the opposite direction as the flow.

        Returns:
            int: The amount of bytes.

        """

        return self.byte_data[PacketDirection.FORWARD]['header_size_min']

    def get_reverse_rate(self) -> int:
        """Calculates the rate of the bytes being going reverse
        in the current flow.

        Returns:
            float: The bytes/sec reverse.

        """
        reverse = self.get_reverse_header_bytes()

        if self.duration == 0:
            rate = -1
        else:
            rate = reverse / self.duration

        return rate

    def get_header_in_out_ratio(self) -> float:
        """Calculates the ratio of foward traffic over reverse traffic.

        Returns:
            float: The ratio over reverse traffic.
            If the reverse header bytes is 0 this returns -1 to avoid
            a possible division by 0.

        """
        reverse_header_bytes = self.get_reverse_header_bytes()
        forward_header_bytes = self.get_forward_header_bytes()

        ratio = -1
        if reverse_header_bytes != 0:
            ratio = forward_header_bytes / reverse_header_bytes

        return ratio

    def get_bytes_per_bulk(self, packet_direction):
        if packet_direction == PacketDirection.FORWARD:
            if self.feature.forward_bulk_count != 0:
                return self.feature.forward_bulk_size / self.feature.forward_bulk_count
        else:
            if self.feature.backward_bulk_count != 0:
                return (
                        self.feature.backward_bulk_size / self.feature.backward_bulk_count
                )
        return 0

    def get_packets_per_bulk(self, packet_direction):
        if packet_direction == PacketDirection.FORWARD:
            if self.feature.forward_bulk_count != 0:
                return (
                        self.feature.forward_bulk_packet_count
                        / self.feature.forward_bulk_count
                )
        else:
            if self.feature.backward_bulk_count != 0:
                return (
                        self.feature.backward_bulk_packet_count
                        / self.feature.backward_bulk_count
                )
        return 0

    def get_bulk_rate(self, packet_direction):
        if packet_direction == PacketDirection.FORWARD:
            if self.feature.forward_bulk_count != 0 and self.feature.forward_bulk_duration > 0:
                return (
                        self.feature.forward_bulk_size / self.feature.forward_bulk_duration
                )
        else:
            if self.feature.backward_bulk_count != 0 and self.feature.backward_bulk_duration > 0:
                return (
                        self.feature.backward_bulk_size
                        / self.feature.backward_bulk_duration
                )
        return 0
