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
from src.flow_meter_features.packet_bulk import BulkPacketData
from src.flow_meter_features.constants import EXPIRED_UPDATE, GARBAGE_COLLECT_PACKETS
from src.clean_ip import _format_ip
from dataclasses import dataclass


class Flow:
    """This class summarizes the values of the features of the network flows"""

    def __init__(self, flow_key: Any) -> None:
        """This method initializes an object from the Flow class.

        Args:
            packet (Any): A packet from the network.
            direction (Enum): The direction the packet is going ove the wire.
        """

        (
            self.source,
            self.destination,
            self.source_port,
            self.destination_port
        ) = flow_key

        self.ack = 0
        self.protocol = 0
        self.init_window_size = {
            PacketDirection.FORWARD: 0,
            PacketDirection.REVERSE: 0,
        }

        self.flow_bytes = FlowBytes()
        self.packet_bulk = BulkPacketData()
        self.flag_count = FlagCount()
        self.packet_count = PacketCount()
        self.packet_length = PacketLength()
        self.packet_time = PacketTime()
        self.active_idle = ActiveIdle()
        self.duration = 0.0
        self.num_features = len(self.get_data())
        self.completed = False
        self.prediction = None

    def update_flow_duration(self, packet_time: float) -> bool:
        self.duration = packet_time - self.packet_time.get_first_timestamp()

        if self.duration >= EXPIRED_UPDATE:
            self.completed = True

        return self.completed

    def get_data(self, direction: PacketDirection=None) -> dict:
        """This method obtains the values of the features extracted from each flow.

        Note:
            Only some of the network data plays well together in this list.
            Time-to-live values, window values, and flags cause the data to
            separate out too much.

        Returns:
           list: returns a List of values to be outputted into a csv file.

        """

        # src_ip_as_int = _format_ip(self.src_ip, "auto", "integer", "raise")
        # dst_ip_as_int = _format_ip(self.dst_ip, "auto", "integer", "raise")
        # self.duration = self.packet_time.get_flow_duration()

        data = {
            # Basic IP information
            "src_node_id": self.source[0],
            "dst_node_id": self.destination[0],
            "src_ip": self.source[1],
            "dst_ip": self.destination[1],
            "src_port": self.source_port,
            "dst_port": self.destination_port,
            "protocol": self.protocol,
            "pkt_length": self.packet_length.packet_lengths[direction],
            "info": self.ack,
            # Basic information from packet times
            "timestamp": self.packet_time.timestamps[direction]['last_timestamp'],
            "flow_duration": self.duration,  # self.packet_time.get_flow_duration(),
            "flow_byts_s": self.flow_bytes.get_rate(self.duration),
            "flow_pkts_s": self.packet_count.get_rate(self.duration),
            "fwd_pkts_s": self.packet_count.get_rate(self.packet_time.get_flow_duration(PacketDirection.FORWARD),
                                                     PacketDirection.FORWARD),
            "bwd_pkts_s": self.packet_count.get_rate(self.packet_time.get_flow_duration(PacketDirection.REVERSE),
                                                     PacketDirection.REVERSE),
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
                self.packet_bulk.get_bytes_per_bulk(PacketDirection.FORWARD)
            ),
            "fwd_pkts_b_avg": float(
                self.packet_bulk.get_packets_per_bulk(PacketDirection.FORWARD)
            ),
            "bwd_byts_b_avg": float(
                self.packet_bulk.get_bytes_per_bulk(PacketDirection.REVERSE)
            ),
            "bwd_pkts_b_avg": float(
                self.packet_bulk.get_packets_per_bulk(PacketDirection.REVERSE)
            ),
            "fwd_blk_rate_avg": float(
                self.packet_bulk.get_bulk_rate(PacketDirection.FORWARD)
            ),
            "bwd_blk_rate_avg": float(
                self.packet_bulk.get_bulk_rate(PacketDirection.REVERSE)
            ),
        }

        return data

    def set_window_size(self, packet: Any, direction: PacketDirection) -> None:

        if self.init_window_size[direction] == 0:
            self.init_window_size[direction] = packet['TCP'].window

    def get_protocol(self, packet: Any) -> None:

        # if self.packet_time.timestamps[None]['first_timestamp'] == 0:
        if 'TCP' in packet:
            self.protocol = 6
        if 'UDP' in packet:
            self.protocol = 17

    def get_short_flow_output(self) -> str:
        proto = {
            0: '%NA',
            6: 'TCP',
            17: 'UDP'
        }
        return '[' + str(self.source[1]) + '(' + str(self.source_port) + ') <----------> ' + str(self.destination[1]) + '(' + str(
            self.destination_port) + ') ' + str(self.packet_time.get_flow_duration()) + ' ' + proto[self.protocol] + ' ' + str(self.packet_count.get_total()) + ' ' + str(self.prediction) + ']\n'

    def get_data_as_list(self, direction: PacketDirection=None) -> list:

        return [*map(float, [self.source_port,
                             self.destination_port,
                             self.protocol,
                             self.packet_length.packet_lengths[direction],
                             self.ack,
                             self.packet_time.timestamps[direction]['last_timestamp'],
                             self.duration,
                             self.flow_bytes.get_rate(self.duration),
                             self.packet_count.get_rate(self.duration),
                             self.packet_count.get_rate(self.packet_time.get_flow_duration(PacketDirection.FORWARD),
                                                        PacketDirection.FORWARD),
                             self.packet_count.get_rate(self.packet_time.get_flow_duration(PacketDirection.REVERSE),
                                                        PacketDirection.REVERSE),
                             self.packet_count.get_total(PacketDirection.FORWARD),
                             self.packet_count.get_total(PacketDirection.REVERSE),
                             self.packet_length.get_max(),
                             self.packet_length.get_min(),
                             self.packet_length.get_mean(),
                             self.packet_length.get_standard_deviation(),
                             self.packet_length.get_variance(),
                             self.packet_length.get_sum(PacketDirection.FORWARD),
                             self.packet_length.get_max(PacketDirection.FORWARD),
                             self.packet_length.get_min(PacketDirection.FORWARD),
                             self.packet_length.get_mean(PacketDirection.FORWARD),
                             self.packet_length.get_standard_deviation(PacketDirection.FORWARD),
                             self.packet_length.get_sum(PacketDirection.REVERSE),
                             self.packet_length.get_max(PacketDirection.REVERSE),
                             self.packet_length.get_min(PacketDirection.REVERSE),
                             self.packet_length.get_mean(PacketDirection.REVERSE),
                             self.packet_length.get_standard_deviation(PacketDirection.REVERSE),
                             self.flow_bytes.get_forward_header_bytes(),
                             self.flow_bytes.get_reverse_header_bytes(),
                             self.flow_bytes.get_min_forward_header_bytes(),
                             self.packet_count.get_payload_count(PacketDirection.FORWARD),
                             self.packet_time.get_mean(),
                             self.packet_time.get_max(),
                             self.packet_time.get_min(),
                             self.packet_time.get_standard_deviation(),
                             self.packet_time.get_sum(PacketDirection.FORWARD),
                             self.packet_time.get_max(PacketDirection.FORWARD),
                             self.packet_time.get_min(PacketDirection.FORWARD),
                             self.packet_time.get_mean(PacketDirection.FORWARD),
                             self.packet_time.get_standard_deviation(PacketDirection.FORWARD),
                             self.packet_time.get_sum(PacketDirection.REVERSE),
                             self.packet_time.get_max(PacketDirection.REVERSE),
                             self.packet_time.get_min(PacketDirection.REVERSE),
                             self.packet_time.get_mean(PacketDirection.REVERSE),
                             self.packet_time.get_standard_deviation(PacketDirection.REVERSE),
                             self.flag_count.flag_count("P", PacketDirection.FORWARD),
                             self.flag_count.flag_count("P", PacketDirection.REVERSE),
                             self.flag_count.flag_count("U", PacketDirection.FORWARD),
                             self.flag_count.flag_count("U", PacketDirection.REVERSE),
                             self.flag_count.flag_count("F"),
                             self.flag_count.flag_count("S"),
                             self.flag_count.flag_count("R"),
                             self.flag_count.flag_count("P"),
                             self.flag_count.flag_count("A"),
                             self.flag_count.flag_count("U"),
                             self.flag_count.flag_count("E"),
                             self.packet_count.get_down_up_ratio(),
                             self.packet_length.get_avg(),
                             self.init_window_size[PacketDirection.FORWARD],
                             self.init_window_size[PacketDirection.REVERSE],
                             self.active_idle.active_stats.get_max(),
                             self.active_idle.active_stats.get_min(),
                             self.active_idle.active_stats.get_mean(),
                             self.active_idle.active_stats.get_standard_deviation(),
                             self.active_idle.idle_stats.get_max(),
                             self.active_idle.idle_stats.get_min(),
                             self.active_idle.idle_stats.get_mean(),
                             self.active_idle.idle_stats.get_standard_deviation(),
                             self.packet_bulk.get_bytes_per_bulk(PacketDirection.FORWARD),
                             self.packet_bulk.get_packets_per_bulk(PacketDirection.FORWARD),
                             self.packet_bulk.get_bytes_per_bulk(PacketDirection.REVERSE),
                             self.packet_bulk.get_packets_per_bulk(PacketDirection.REVERSE),
                             self.packet_bulk.get_bulk_rate(PacketDirection.FORWARD),
                             self.packet_bulk.get_bulk_rate(PacketDirection.REVERSE)
                             ]
                     )
                ]

    def __repr__(self) -> str:

        return json.dumps(self.get_data(), sort_keys=False, indent=4, use_decimal=True)