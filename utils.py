import argparse
import csv
import logging
import scapy.layers.inet
from scapy.all import *
import os
from PacketCounter import PacketCounter

log = logging.getLogger('main.utils')


def parse_command_line():
    parser = argparse.ArgumentParser('Extract fields from PCAP files and write them to CSV file')
    parser.add_argument('-v', '--verbose', help='verbose display of packet parsing instead of progress messages', action='store_true')

    # set up a group where the file or directory selection is mutually exclusive and required
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input_file', help='Input PCAP File to be parsed and converted to CSV',
                        type=check_file)
    group.add_argument('-r', '--input_directory', help='Input directory of PCAP Files to be parsed and converted to CSV',
                        type=check_directory)
    parser.add_argument('-o', '--output_file', help='Name of output CSV file to be written', required=True)
    parser.add_argument('-k', '--keep_incomplete', help='Keep packets that do not have all the information to be parsed', action='store_true')

    global gl_args
    gl_args = parser.parse_args()


def check_file(path):
    if not os.path.exists(path):
        raise argparse.ArgumentError('File at: ' + path + ' does not exist')

    if os.access(path, os.R_OK):
        return path
    else:
        raise argparse.ArgumentError('File at: ' + path + ' is not readable')


def check_directory(path):
    # Validate that the path is a directory
    if not os.path.isdir(path):
        raise argparse.ArgumentTypeError('Directory does not exist')

    # Validate the path is readable
    if os.access(path, os.R_OK):
        return path
    else:
        raise argparse.ArgumentTypeError('Directory is not readable')


def packet_handler(output_file):

    packet_counter = PacketCounter()

    def parse_packet(pkt):

        if packet_counter.get_packet_count() == 0:
            packet_counter.set_start_time(pkt.time)

        packet_counter.increment()
        pkt.frame = packet_counter.get_packet_count()
        time_elapsed = pkt.time - packet_counter.get_start_time()
        pkt_length = pkt.wirelen
        ip_src = None
        ip_dst = None
        protocol = None
        info = None

        if scapy.layers.inet.IP in pkt:
            ip_src = pkt[scapy.layers.inet.IP].src
            ip_dst = pkt[scapy.layers.inet.IP].dst
            protocol = pkt[scapy.layers.inet.IP].proto

        if scapy.layers.inet.TCP in pkt:
            info = pkt[scapy.layers.inet.TCP].ack

        target = 0

        if gl_args.verbose:
            print(pkt.frame, time_elapsed, ip_src, ip_dst, protocol, pkt_length, info, target, end='\n')

        if None not in (time_elapsed, ip_src, ip_dst, protocol, info) or gl_args.keep_incomplete:
            output_file.writeCSVRow(pkt.frame, time_elapsed, ip_src, ip_dst, protocol, pkt_length, info, target)

    return parse_packet
