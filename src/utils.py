import logging
import os
import random
import numpy as np
from scipy.stats import entropy
from scapy.all import Raw
from argparse import ArgumentParser, ArgumentError, ArgumentTypeError, Namespace

log = logging.getLogger('main.utils')


def parse_command_line() -> Namespace:
    parser = ArgumentParser('Extract fields from PCAP files and write them to CSV file')
    parser.add_argument('-v', '--verbose', help='verbose display of packet parsing instead of progress messages', action='store_true')

    # set up a group where the file or directory selection is mutually exclusive and required
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input_file', help='Input PCAP File to be parsed and converted to CSV',
                        type=check_file)
    group.add_argument('-r', '--input_directory', help='Input directory of PCAP Files to be parsed and converted to CSV',
                        type=check_directory)
    parser.add_argument('-o', '--output_database_name', help='Name of output sqlite database for graph data files to be written', required=True)
    gl_args = parser.parse_args()

    return gl_args


def check_file(path) -> str:
    if not os.path.exists(path):
        raise ArgumentError('File at: ' + path + ' does not exist')

    if os.access(path, os.R_OK):
        return path
    else:
        raise ArgumentError('File at: ' + path + ' is not readable')


def check_directory(path) -> str:
    # Validate that the path is a directory
    if not os.path.isdir(path):
        raise ArgumentTypeError('Directory does not exist')

    # Validate the path is readable
    if os.access(path, os.R_OK):
        return path
    else:
        raise ArgumentTypeError('Directory is not readable')


def pretty_time_delta(seconds) -> str:
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days > 0:
        return '%dd %dh %dm %ds' % (days, hours, minutes, seconds)
    elif hours > 0:
        return '%dh %dm %ds' % (hours, minutes, seconds)
    elif minutes > 0:
        return '%dm %ds' % (minutes, seconds)
    else:
        return '%ds' % (seconds,)


def generate_unique_integers(n):
    if n < 1:
        return []
    population = range(1, n + 1)
    return random.sample(population, k=n)


def calculate_packet_entropy(packet):
    """Calculates the Shannon entropy of a Scapy packet payload."""
    if not packet.haslayer(Raw):
        return 0.0

    # Get raw bytes from payload
    data = bytes(packet[Raw].load)
    if not data:
        return 0.0

    # 1. Efficiently count byte frequencies (0-255)
    _, counts = np.unique(list(data), return_counts=True)

    # 2. Compute Shannon Entropy using scipy (base 2 for bits)
    return entropy(counts, base=2)
