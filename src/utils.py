import logging
import os
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
    parser.add_argument('-o', '--output_directory', help='Name of output directory for graph data files to be written', required=True)
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
