from src.flow_meter_features.context.packet_direction import PacketDirection


class FlagCount:
    """This class extracts features related to the Flags Count."""

    def __init__(self) -> None:
        self.flags = {
                "F": 0,  # FIN
                "S": 0,  # SYN
                "R": 0,  # RST
                "P": 0,  # PSH
                "A": 0,  # ACK
                "U": 0,  # URG
                "E": 0,  # ECE
                "C": 0,  # CWR
                "N": 0  # Nonce
            }

    def process_packet(self, packet) -> None:

        pkt_flags = ''
        if 'TCP' in packet:
            pkt_flags = str(packet['TCP'].flags)

        for flag in pkt_flags:
            self.flags[flag] += 1

    def flag_count(self, flag) -> int:

        return self.flags[flag]
