from src.flow_meter_features.context.packet_direction import PacketDirection


class FlowBytes:
    """Extracts features from the traffic related to the bytes in a flow"""

    def __init__(self) -> None:

        self.byte_data = {
                'total_bytes': 0,
                'header_size_sum': 0,
                'header_size_min': 0,
                'header_size_max': 0
            }

    def process_packet(self, packet) -> None:

        self.byte_data['total_bytes'] += len(packet)

        self.byte_data['header_size_sum'] += self._header_size(packet)

        self.byte_data['header_size_min'] = min(self.byte_data['header_size_min'],
                                                      self._header_size(packet))

        self.byte_data['header_size_max'] = max(self.byte_data['header_size_max'],
                                                      self._header_size(packet))

    @staticmethod
    def _header_size(packet) -> int:

        if 'TCP' in packet:
            return 20 + packet['TCP'].dataofs
        return 8

    def get_bytes(self) -> int:
        """Calculates the amount bytes being transfered.

        Returns:
            int: The amount of bytes.

        """
        return self.byte_data['total_bytes']

    def get_rate(self, duration) -> float:
        """Calculates the rate of the bytes being transfered in the current flow.

        Returns:
            float: The bytes/sec sent.

        """

        if duration > 1:
            return self.get_bytes() / duration

        return 0.0


    def get_header_bytes(self) -> int:
        """Calculates the amount of header bytes in the header sent

        Returns:
            int: The amount of bytes.

        """

        return self.byte_data['header_size_sum']

    def get_header_rate(self, duration) -> float:
        """Calculates the rate of the bytes being going forward
        in the current flow.

        Returns:
            float: The bytes/sec forward.

        """

        if duration > 1:
            return self.get_header_bytes() / duration

        return 0.0


    def get_min_header_bytes(self) -> int:
        """Calculates the amount of header bytes in the header sent in the opposite direction as the flow.

        Returns:
            int: The amount of bytes.

        """

        return self.byte_data['header_size_min']

    def get_max_header_bytes(self) -> int:
        """Calculates the amount of header bytes in the header sent in the opposite direction as the flow.

        Returns:
            int: The amount of bytes.

        """

        return self.byte_data['header_size_max']

