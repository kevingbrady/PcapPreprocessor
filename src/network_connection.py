import time
import simplejson as json
import hashlib
from enum import Enum
from typing import Any

from src.flow_meter_features import constants
from src.flow_meter_features.context.packet_direction import PacketDirection
from src.flow_meter_features.flag_count import FlagCount
from src.flow_meter_features.flow_bytes import FlowBytes
from src.flow_meter_features.packet_count import PacketCount
from src.flow_meter_features.packet_time import PacketTime
from src.flow_meter_features.packet_length import PacketLength
from src.flow_meter_features.active_idle import ActiveIdle
from src.flow_meter_features.constants import EXPIRED_UPDATE


class NetworkConnection:
    """This class summarizes the values of the features of the network flows"""

    def __init__(self, flow_key: Any) -> None:
        """This method initializes an object from the Flow class.

        Args:
            packet (Any): A packet from the network.
        """

        (
            self.source,
            self.destination,
            self.source_port,
            self.destination_port
        ) = flow_key

        self.ack = 0
        self.protocol = 0
        self.init_window_size = 0

        self.flow_bytes = FlowBytes()
        self.flag_count = FlagCount()
        self.packet_count = PacketCount()
        self.packet_length = PacketLength()
        self.packet_time = PacketTime()
        self.active_idle = ActiveIdle()
        self.duration = 0.0
        self.num_features = len(self.get_data())
        self.completed = False

    def get_data(self) -> dict:

        data = {
            # Basic Connection information
            "src_ip": self.source,
            "dst_ip": self.destination,
            "src_port": self.source_port,
            "dst_port": self.destination_port,
            "protocol": self.protocol,
            "info": self.ack,
            # Packet Time
            "timestamp": self.packet_time.get_latest_timestamp(),
            "flow_duration": self.duration,
            # Connection Interarrival Time
            "conn_iat": self.packet_time.iat,
            "conn_iat_mean": self.packet_time.get_mean(),
            "conn_iat_max": self.packet_time.get_max(),
            "conn_iat_min": self.packet_time.get_min(),
            "conn_iat_std": self.packet_time.get_standard_deviation(),
            # Connection Bytes
            "init_win_byts": self.init_window_size,
            "header_len": self.flow_bytes.get_header_bytes(),
            "header_size_min": self.flow_bytes.get_min_header_bytes(),
            "header_size_max": self.flow_bytes.get_max_header_bytes(),
            "flow_byts_s": self.flow_bytes.get_rate(self.duration),
            # Connection Packet Counts
            "connection_packet_count": self.packet_count.get_total(),
            "flow_pkts_s": self.packet_count.get_rate(self.duration),
            "payload_count": self.packet_count.get_payload_count(),
            # Connection Packet Lengths
            "pkt_length": self.packet_length.packet_length,
            "pkt_len_avg": self.packet_length.get_avg(),
            "pkt_len_max": self.packet_length.get_max(),
            "pkt_len_min": self.packet_length.get_min(),
            "pkt_len_mean": self.packet_length.get_mean(),
            "pkt_len_std": self.packet_length.get_standard_deviation(),
            "pkt_len_var": self.packet_length.get_variance(),
            # Flags stats
            "fin_flag_cnt": self.flag_count.flag_count("F"),
            "syn_flag_cnt": self.flag_count.flag_count("S"),
            "rst_flag_cnt": self.flag_count.flag_count("R"),
            "psh_flag_cnt": self.flag_count.flag_count("P"),
            "ack_flag_cnt": self.flag_count.flag_count("A"),
            "urg_flag_cnt": self.flag_count.flag_count("U"),
            "ece_flag_cnt": self.flag_count.flag_count("E"),
            # Active/Idle stats
            "active_max": self.active_idle.active_stats.get_max(),
            "active_min": self.active_idle.active_stats.get_min(),
            "active_mean": self.active_idle.active_stats.get_mean(),
            "active_std": self.active_idle.active_stats.get_standard_deviation(),
            "idle_max": self.active_idle.idle_stats.get_max(),
            "idle_min": self.active_idle.idle_stats.get_min(),
            "idle_mean": self.active_idle.idle_stats.get_mean(),
            "idle_std": self.active_idle.idle_stats.get_standard_deviation()
        }

        return data

    def set_window_size(self, packet: Any) -> None:

        if self.init_window_size == 0:
            self.init_window_size = packet['TCP'].window

    def get_protocol(self, packet: Any) -> None:

        # if self.packet_time.timestamps[None]['first_timestamp'] == 0:
        if 'TCP' in packet:
            self.protocol = 6
        if 'UDP' in packet:
            self.protocol = 17

    def get_short_connection_output(self) -> str:
        proto = {
            0: '%NA',
            6: 'TCP',
            17: 'UDP'
        }
        return '[' + str(self.source[1]) + '(' + str(self.source_port) + ') <----------> ' + str(
            self.destination[1]) + '(' + str(
            self.destination_port) + ') ' + str(self.packet_time.get_flow_duration()) + ' ' + proto[
            self.protocol] + ' ' + str(self.packet_count.get_total()) + ' ' + str(self.prediction) + ']\n'

    def get_data_as_list(self) -> list:

        return [*map(float, [
            self.source_port,
            self.destination_port,
            self.protocol,
            self.ack,
            self.packet_time.get_latest_timestamp(),
            self.duration,
            self.packet_time.get_packet_iat(self.packet_time.get_latest_timestamp()),
            self.packet_time.get_mean(),
            self.packet_time.get_max(),
            self.packet_time.get_min(),
            self.packet_time.get_standard_deviation(),
            self.init_window_size,
            self.flow_bytes.get_header_bytes(),
            self.flow_bytes.get_min_header_bytes(),
            self.flow_bytes.get_max_header_bytes(),
            self.flow_bytes.get_rate(self.duration),
            self.packet_count.get_total(),
            self.packet_count.get_rate(self.duration),
            self.packet_count.get_payload_count(),
            self.packet_length.packet_length,
            self.packet_length.get_avg(),
            self.packet_length.get_max(),
            self.packet_length.get_min(),
            self.packet_length.get_mean(),
            self.packet_length.get_standard_deviation(),
            self.packet_length.get_variance(),
            self.flag_count.flag_count("F"),
            self.flag_count.flag_count("S"),
            self.flag_count.flag_count("R"),
            self.flag_count.flag_count("P"),
            self.flag_count.flag_count("A"),
            self.flag_count.flag_count("U"),
            self.flag_count.flag_count("E"),
            self.active_idle.active_stats.get_max(),
            self.active_idle.active_stats.get_min(),
            self.active_idle.active_stats.get_mean(),
            self.active_idle.active_stats.get_standard_deviation(),
            self.active_idle.idle_stats.get_max(),
            self.active_idle.idle_stats.get_min(),
            self.active_idle.idle_stats.get_mean(),
            self.active_idle.idle_stats.get_standard_deviation()
        ])]

    def __repr__(self) -> str:

        return json.dumps(self.get_data(), sort_keys=False, indent=4, use_decimal=True)
