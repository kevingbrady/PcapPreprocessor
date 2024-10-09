from src.flow_meter_features.context.packet_direction import PacketDirection


class FlagCount:
    """This class extracts features related to the Flags Count."""

    flags = {
        None: {
            "F": 0,  # FIN
            "S": 0,  # SYN
            "R": 0,  # RST
            "P": 0,  # PSH
            "A": 0,  # ACK
            "U": 0,  # URG
            "E": 0,  # ECE
            "C": 0,  # CWR
            "N": 0  # Nonce
        },
        PacketDirection.FORWARD: {
            "F": 0,  # FIN
            "S": 0,  # SYN
            "R": 0,  # RST
            "P": 0,  # PSH
            "A": 0,  # ACK
            "U": 0,  # URG
            "E": 0,  # ECE
            "C": 0,  # CWR
            "N": 0  # Nonce
        },
        PacketDirection.REVERSE: {
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
    }

    def process_packet(self, packet, direction):

        pkt_flags = ''
        if 'TCP' in packet:
            pkt_flags = str(packet['TCP'].flags)

        for flag in pkt_flags:
            self.flags[None][flag] += 1
            self.flags[direction][flag] += 1

    def flag_count(self, flag, direction=None):

        return self.flags[direction][flag]
