from src.flow_meter_features.context.packet_direction import PacketDirection


class FlowBytes:
    """Extracts features from the traffic related to the bytes in a flow"""

    def __init__(self) -> None:

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

    def process_packet(self, packet, direction) -> None:

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
    def _header_size(packet) -> int:

        if 'TCP' in packet:
            return 20 + packet['TCP'].dataofs
        return 8

    def get_bytes(self, direction=None) -> int:
        """Calculates the amount bytes being transfered.

        Returns:
            int: The amount of bytes.

        """
        return self.byte_data[direction]['total_bytes']

    def get_rate(self, duration) -> float:
        """Calculates the rate of the bytes being transfered in the current flow.

        Returns:
            float: The bytes/sec sent.

        """

        if duration > 1:
            return self.get_bytes() / duration

        return 0.0

    def get_bytes_sent(self) -> int:
        """Calculates the amount bytes sent from the machine being used to run DoHlyzer.

        Returns:
            int: The amount of bytes.

        """
        return self.get_bytes(PacketDirection.FORWARD)

    def get_sent_rate(self, duration) -> float:
        """Calculates the rate of the bytes being sent in the current flow.

        Returns:
            float: The bytes/sec sent.

        """

        if duration > 1:
            return self.get_bytes_sent() / duration

        return 0.0

    def get_bytes_received(self) -> int:
        """Calculates the amount bytes received.

        Returns:
            int: The amount of bytes.

        """
        return self.get_bytes(PacketDirection.REVERSE)

    def get_received_rate(self, duration) -> float:
        """Calculates the rate of the bytes being received in the current flow.

        Returns:
            float: The bytes/sec received.

        """

        if duration > 1:
            return self.get_bytes_received() / duration

        return 0.0

    def get_forward_header_bytes(self) -> int:
        """Calculates the amount of header bytes in the header sent in the same direction as the flow.

        Returns:
            int: The amount of bytes.

        """

        return self.byte_data[PacketDirection.FORWARD]['header_size_sum']

    def get_forward_rate(self, duration) -> float:
        """Calculates the rate of the bytes being going forward
        in the current flow.

        Returns:
            float: The bytes/sec forward.

        """

        if duration > 1:
            return self.get_forward_header_bytes() / duration

        return 0.0

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

    def get_reverse_rate(self, duration) -> float:
        """Calculates the rate of the bytes being going reverse
        in the current flow.

        Returns:
            float: The bytes/sec reverse.

        """

        if duration > 1:
            return self.get_reverse_header_bytes() / duration

        return 0.0

    def get_header_in_out_ratio(self) -> float:
        """Calculates the ratio of foward traffic over reverse traffic.

        Returns:
            float: The ratio over reverse traffic.
            If the reverse header bytes is 0 this returns -1 to avoid
            a possible division by 0.

        """
        reverse_header_bytes = self.get_reverse_header_bytes()
        forward_header_bytes = self.get_forward_header_bytes()

        if reverse_header_bytes > 1:
            return forward_header_bytes / reverse_header_bytes

        return 0.0

