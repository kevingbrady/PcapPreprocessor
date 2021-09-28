from enum import Enum
from typing import Any

from src.flow_meter_features import constants
from src.flow_meter_features.context import packet_flow_key
from src.flow_meter_features.context.packet_direction import PacketDirection
from src.flow_meter_features.flag_count import FlagCount
from src.flow_meter_features.flow_bytes import FlowBytes
from src.flow_meter_features.packet_count import PacketCount
from src.flow_meter_features.packet_time import PacketTime
from src.flow_meter_features.packet_length import PacketLength
from src.flow_meter_features.active_idle import ActiveIdle
from scapy.layers.inet6 import IPv6
from scapy.layers.inet import IP, TCP, UDP
from src.clean_ip import _format_ip


class Flow:
    """This class summarizes the values of the features of the network flows"""

    def __init__(self, packet: Any, direction: Enum):
        """This method initializes an object from the Flow class.

        Args:
            packet (Any): A packet from the network.
            direction (Enum): The direction the packet is going ove the wire.
        """

        (
            self.dest_ip,
            self.src_ip,
            self.src_port,
            self.dest_port,
        ) = packet_flow_key.get_packet_fields(packet, direction)

        self.latest_timestamp = 0
        self.start_timestamp = 0
        self.init_window_size = {
            PacketDirection.FORWARD: 0,
            PacketDirection.REVERSE: 0,
        }

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

        self.flow_bytes = FlowBytes(self)
        self.flag_count = FlagCount()
        self.packet_count = PacketCount()
        self.packet_length = PacketLength()
        self.packet_time = PacketTime()
        self.active_idle = ActiveIdle()

    def get_data(self, packet, direction) -> dict:
        """This method obtains the values of the features extracted from each flow.

        Note:
            Only some of the network data plays well together in this list.
            Time-to-live values, window values, and flags cause the data to
            separate out too much.

        Returns:
           list: returns a List of values to be outputted into a csv file.

        """

        self.packet_time.process_packet(packet, direction)
        self.flow_bytes.process_packet(packet, direction)
        self.packet_count.process_packet(packet, direction)
        self.packet_length.process_packet(packet, direction)
        self.flag_count.process_packet(packet, direction)
        self.active_idle.process_packet(packet, direction)

        self.packet_count.duration = self.packet_time.get_duration()
        self.flow_bytes.duration = self.packet_time.get_duration()

        self.update_flow_bulk(packet, direction)
        self.set_window_size(packet, direction)
        self.latest_timestamp = self.packet_time.get_timestamp()

        clean_ip_src = _format_ip(self.src_ip, "auto", "integer", "raise")
        clean_ip_dst = _format_ip(self.dest_ip, "auto", "integer", "raise")

        ack = 0

        if TCP in packet:
            ack = packet[TCP].ack

        data = {
            # Basic IP information
            "src_ip": clean_ip_src[0],
            "dst_ip": clean_ip_dst[0],
            "src_port": self.src_port,
            "dst_port": self.dest_port,
            "protocol": self.get_protocol(packet),
            "pkt_length": len(packet),
            "info": ack,
            # Basic information from packet times
            "timestamp": self.latest_timestamp,
            "flow_duration": 1e6 * self.packet_time.get_duration(),
            "flow_byts_s": self.flow_bytes.get_rate(),
            "flow_pkts_s": self.packet_count.get_rate(),
            "fwd_pkts_s":self.packet_count.get_rate(PacketDirection.FORWARD),
            "bwd_pkts_s": self.packet_count.get_rate(PacketDirection.REVERSE),
            # Count total packets by direction
            "tot_fwd_pkts": self.packet_count.get_total(PacketDirection.FORWARD),
            "tot_bwd_pkts": self.packet_count.get_total(PacketDirection.REVERSE),
            # Statistical info obtained from Packet lengths
            "pkt_len_max": self.packet_length.get_max(),
            "pkt_len_min": self.packet_length.get_min(),
            "pkt_len_mean": self.packet_length.get_mean(),
            "pkt_len_std": self.packet_length.get_standard_deviation(),
            "pkt_len_var": self.packet_length.get_variance(),
            "totlen_fwd_pkts": self.packet_length.get_sum(PacketDirection.FORWARD),
            "fwd_pkt_len_max": self.packet_length.get_max(PacketDirection.FORWARD),
            "fwd_pkt_len_min": self.packet_length.get_min(PacketDirection.FORWARD),
            "fwd_pkt_len_mean": self.packet_length.get_mean(PacketDirection.FORWARD),
            "fwd_pkt_len_std": self.packet_length.get_standard_deviation(PacketDirection.FORWARD),
            "totlen_bwd_pkts": self.packet_length.get_sum(PacketDirection.REVERSE),
            "bwd_pkt_len_max": self.packet_length.get_max(PacketDirection.REVERSE),
            "bwd_pkt_len_min": self.packet_length.get_min(PacketDirection.REVERSE),
            "bwd_pkt_len_mean": self.packet_length.get_mean(PacketDirection.REVERSE),
            "bwd_pkt_len_std": self.packet_length.get_standard_deviation(PacketDirection.REVERSE),
            "fwd_header_len": self.flow_bytes.get_forward_header_bytes(),
            "bwd_header_len": self.flow_bytes.get_reverse_header_bytes(),
            "fwd_seg_size_min": self.flow_bytes.get_min_forward_header_bytes(),
            "fwd_act_data_pkts": self.packet_count.get_payload_count(PacketDirection.FORWARD),
            # Flows Interarrival Time
            "flow_iat_mean": self.packet_time.get_mean(),
            "flow_iat_max": self.packet_time.get_max(),
            "flow_iat_min": self.packet_time.get_min(),
            "flow_iat_std": self.packet_time.get_standard_deviation(),
            "fwd_iat_tot": self.packet_time.get_sum(PacketDirection.FORWARD),
            "fwd_iat_max": self.packet_time.get_max(PacketDirection.FORWARD),
            "fwd_iat_min": self.packet_time.get_min(PacketDirection.FORWARD),
            "fwd_iat_mean": self.packet_time.get_mean(PacketDirection.FORWARD),
            "fwd_iat_std": self.packet_time.get_standard_deviation(PacketDirection.FORWARD),
            "bwd_iat_tot": self.packet_time.get_sum(PacketDirection.REVERSE),
            "bwd_iat_max": self.packet_time.get_max(PacketDirection.REVERSE),
            "bwd_iat_min": self.packet_time.get_min(PacketDirection.REVERSE),
            "bwd_iat_mean": self.packet_time.get_mean(PacketDirection.REVERSE),
            "bwd_iat_std": self.packet_time.get_standard_deviation(PacketDirection.REVERSE),
            # Flags statistics
            "fwd_psh_flags": self.flag_count.flag_count("P", PacketDirection.FORWARD),
            "bwd_psh_flags": self.flag_count.flag_count("P", PacketDirection.REVERSE),
            "fwd_urg_flags": self.flag_count.flag_count("U", PacketDirection.FORWARD),
            "bwd_urg_flags": self.flag_count.flag_count("U", PacketDirection.REVERSE),
            "fin_flag_cnt": self.flag_count.flag_count("F"),
            "syn_flag_cnt": self.flag_count.flag_count("S"),
            "rst_flag_cnt": self.flag_count.flag_count("R"),
            "psh_flag_cnt": self.flag_count.flag_count("P"),
            "ack_flag_cnt": self.flag_count.flag_count("A"),
            "urg_flag_cnt": self.flag_count.flag_count("U"),
            "ece_flag_cnt": self.flag_count.flag_count("E"),
            # Response Time
            "down_up_ratio": self.packet_count.get_down_up_ratio(),
            "pkt_size_avg": self.packet_length.get_avg(),
            "init_fwd_win_byts": self.init_window_size[PacketDirection.FORWARD],
            "init_bwd_win_byts": self.init_window_size[PacketDirection.REVERSE],
            "active_max": self.active_idle.active_stats.get_max(),
            "active_min": self.active_idle.active_stats.get_min(),
            "active_mean": self.active_idle.active_stats.get_mean(),
            "active_std": self.active_idle.active_stats.get_standard_deviation(),
            "idle_max": self.active_idle.idle_stats.get_max(),
            "idle_min": self.active_idle.idle_stats.get_min(),
            "idle_mean": self.active_idle.idle_stats.get_mean(),
            "idle_std": self.active_idle.idle_stats.get_standard_deviation(),
            "fwd_byts_b_avg": float(
                self.flow_bytes.get_bytes_per_bulk(PacketDirection.FORWARD)
            ),
            "fwd_pkts_b_avg": float(
                self.flow_bytes.get_packets_per_bulk(PacketDirection.FORWARD)
            ),
            "bwd_byts_b_avg": float(
                self.flow_bytes.get_bytes_per_bulk(PacketDirection.REVERSE)
            ),
            "bwd_pkts_b_avg": float(
                self.flow_bytes.get_packets_per_bulk(PacketDirection.REVERSE)
            ),
            "fwd_blk_rate_avg": float(
                self.flow_bytes.get_bulk_rate(PacketDirection.FORWARD)
            ),
            "bwd_blk_rate_avg": float(
                self.flow_bytes.get_bulk_rate(PacketDirection.REVERSE)
            ),
        }

        # Duplicated features
        data["fwd_seg_size_avg"] = data["fwd_pkt_len_mean"]
        data["bwd_seg_size_avg"] = data["bwd_pkt_len_mean"]
        data["cwe_flag_count"] = data["fwd_urg_flags"]
        data["subflow_fwd_pkts"] = data["tot_fwd_pkts"]
        data["subflow_bwd_pkts"] = data["tot_bwd_pkts"]
        data["subflow_fwd_byts"] = data["totlen_fwd_pkts"]
        data["subflow_bwd_byts"] = data["totlen_bwd_pkts"]

        return data

    def set_window_size(self, packet, direction):

        if TCP in packet:
            if direction == PacketDirection.FORWARD and self.init_window_size[direction] == 0:
                self.init_window_size[direction] = packet[TCP].window
            elif direction == PacketDirection.REVERSE:
                self.init_window_size[direction] = packet[TCP].window

    def get_protocol(self, packet):

        if UDP in packet and IPv6 in packet:
            protocol = packet[IPv6].nh

        else:
            protocol = packet[IP].proto

        return protocol

    def update_flow_bulk(self, packet, direction):
        """Update bulk flow

        Args:
            packet: Packet to be parse as bulk

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
                if (
                    packet.time - self.forward_bulk_last_timestamp
                ) > constants.CLUMP_TIMEOUT:
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
                        self.forward_bulk_duration += (
                            packet.time - self.forward_bulk_start_tmp
                        )
                    elif self.forward_bulk_count_tmp > constants.BULK_BOUND:
                        self.forward_bulk_packet_count += 1
                        self.forward_bulk_size += payload_size
                        self.forward_bulk_duration += (
                            packet.time - self.forward_bulk_last_timestamp
                        )
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
                if (
                    packet.time - self.backward_bulk_last_timestamp
                ) > constants.CLUMP_TIMEOUT:
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
                        self.backward_bulk_duration += (
                            packet.time - self.backward_bulk_start_tmp
                        )
                    elif self.backward_bulk_count_tmp > constants.BULK_BOUND:
                        self.backward_bulk_packet_count += 1
                        self.backward_bulk_size += payload_size
                        self.backward_bulk_duration += (
                            packet.time - self.backward_bulk_last_timestamp
                        )
                    self.backward_bulk_last_timestamp = packet.time

    @property
    def duration(self):
        return self.latest_timestamp - self.start_timestamp