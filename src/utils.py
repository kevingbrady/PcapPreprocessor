import argparse
import logging
import os

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
    parser.add_argument('-c', '--enable_cicflowmeter', help='Enable calculating cicflowmeter metrics', action='store_true')
    gl_args = parser.parse_args()

    return gl_args


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


def pretty_time_delta(seconds):
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
