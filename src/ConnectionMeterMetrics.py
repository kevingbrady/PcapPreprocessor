import ipaddress
import torch
#from torch_sparse import SparseTensor
from torch_geometric.utils import degree
from enum import Enum
from typing import *
from src.flow_meter_features.context.packet_direction import PacketDirection
from src.network_connection import NetworkConnection
from src.flow_meter_features.constants import EXPIRED_UPDATE
from collections import OrderedDict
from dataclasses import dataclass


@dataclass(frozen=True)
class ConnectionKey:
    source: str
    destination: str
    source_port: int
    destination_port: int

    def __iter__(self):
        yield self.source
        yield self.destination
        yield self.source_port
        yield self.destination_port

    def __eq__(self, other):
        if not isinstance(other, ConnectionKey):
            return NotImplemented
        return (self.source, self.destination, self.source_port, self.destination_port) == (
            other.source, other.destination, other.source_port, other.destination_port)

    def __hash__(self):
        return hash((self.source, self.destination, self.source_port, self.destination_port))


class ConnectionMeterMetrics:

    def __init__(self, *args, **kwargs) -> None:
        self.connections = {}  # OrderedDict()    # graph edges (connections)
        self.packet_count_total = 0

    def get_connection_keys(self, packet: Any) -> tuple[ConnectionKey, ConnectionKey]:

        src_ip, dst_ip, src_port, dst_port = self.get_connection_address_info(packet)

        forward = ConnectionKey(src_ip, dst_ip, src_port, dst_port)
        reverse = ConnectionKey(dst_ip, src_ip, dst_port, src_port)

        return forward, reverse

    @staticmethod
    def get_connection_address_info(packet: Any) -> tuple[str, str, int, int]:

        ip = 'IPv6' if 'IPv6' in packet else 'IP'

        if 'TCP' in packet:
            protocol = 'TCP'
        elif 'UDP' in packet:
            protocol = 'UDP'
        else:
            raise Exception("Only TCP protocols are supported.")

        src_ip = packet[ip].src
        dst_ip = packet[ip].dst
        src_port = packet[protocol].sport
        dst_port = packet[protocol].dport

        return src_ip, dst_ip, src_port, dst_port

    def process_packet(self, packet: Any, filter: bool = False) -> None:

        self.packet_count_total += 1

        connection_key, reverse_connection_key = self.get_connection_keys(packet)

        if filter:

            if self.filter_check(connection_key.source) or self.filter_check(connection_key.destination):
                return

        conn = self.connections.get(connection_key)
        reverse = self.connections.get(connection_key)

        if conn is None:
            conn = NetworkConnection(connection_key)
            self.connections[connection_key] = conn

        if reverse is None:
            reverse = NetworkConnection(reverse_connection_key)
            self.connections[reverse_connection_key] = reverse
            if reverse.packet_time.get_first_timestamp() == 0.0:
                reverse.packet_time.process_packet(packet)

        if 'TCP' in packet:
            conn.ack = packet['TCP'].ack
            conn.set_window_size(packet)

        conn.packet_time.process_packet(packet)
        conn.active_idle.update_active_idle(conn.packet_time.iat)
        conn.packet_count.process_packet(packet)
        conn.packet_length.process_packet(packet)
        conn.flow_bytes.process_packet(packet)
        conn.flag_count.process_packet(packet)
        conn.get_protocol(packet)

        if conn.flag_count.flag_count('R') > 0 or (
                conn.flag_count.flag_count('F') >= 1 and reverse.flag_count.flag_count('F') >= 1):
            conn.completed = True
            reverse.completed = True

        self.garbage_collect(packet.time, reverse)


    def filter_check(self, ip_addr: str)-> bool:

        filter_check = ipaddress.ip_address(ip_addr)
        if filter_check.is_loopback or filter_check.is_multicast or filter_check.is_link_local: # or filter_check.is_private:
            return True
        return False

    def check_connection_completed(self, packet_time: float, connection: NetworkConnection,
                                   reverse: NetworkConnection) -> bool:

        connection.duration = connection.packet_time.get_flow_duration(packet_time)

        if connection.duration >= EXPIRED_UPDATE:
            connection.completed = True
            reverse.completed = True

        return connection.completed

    def get_graph_data(self, starting_timestamp=-1, ending_timestamp=-1, sparse=False):

        if starting_timestamp == -1 or ending_timestamp == -1:
            sparse = False

        nodes = set()
        connections = []
        connection_edge_list = []

        for (src, dst, src_port, dst_port), connection in self.connections.items():

            nodes.add(src)
            nodes.add(dst)

            node_list = list(nodes)
            connection_edge_list.append((node_list.index(src), node_list.index(dst)))

            if sparse:
                if starting_timestamp <= connection.packet_time.get_latest_timestamp() <= ending_timestamp:
                    connections.append(connection.get_data_as_list())
                else:
                    connections.append([0] * (connection.num_features - 2))

            else:
                connections.append(connection.get_data_as_list())

        connections = torch.tensor(connections, dtype=torch.float32)
        connection_edge_list = torch.tensor(connection_edge_list, dtype=torch.long).t().contiguous() if connection_edge_list else torch.empty(2, 0, dtype=torch.long)
        node_features = degree(connection_edge_list[0], len(nodes)).view(-1, 1).to(torch.float32)

        return nodes, node_features, connections, connection_edge_list

    def garbage_collect(self, latest_time, reverse_connection) -> None:

        self.connections = {key: connection for key, connection in self.connections.items() if
                            not connection.completed and not self.check_connection_completed(latest_time, connection,
                                                                                             reverse_connection)}
