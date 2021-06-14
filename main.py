import logging
from scapy.all import *
import pyshark
import logging
import time
import utils
import lxml
from CSVWriter import _CSVWriter

if __name__ == '__main__':

    # Turn on Logging
    logging.basicConfig(filename='PcapPreprocessor.log', filemode='w', level=logging.DEBUG, format='%(asctime)s %(message)s')

    # Record Starting Time
    startTime = time.time()

    # Parse Command Line Arguments
    utils.parse_command_line()

    output_file = _CSVWriter(utils.gl_args.output_file)

    if utils.gl_args.input_file:

        print('----------------------------------------------------')
        print('Parsing file: ' + utils.gl_args.input_file)
        logging.info('Parsing file: ' + utils.gl_args.input_file)
        pcap_file = sniff(offline=utils.gl_args.input_file, prn=utils.packet_handler(output_file), store=0)
        logging.info('File completed: ' + utils.gl_args.input_file)
        print('File completed: ' + utils.gl_args.input_file)
        print('----------------------------------------------------')

    elif utils.gl_args.input_directory:

        logging.info('Directory Parsing Started at: ' + utils.gl_args.input_directory + '/')
        print('Directory Parsing Started at: ' + utils.gl_args.input_directory + '/')

        # Create a loop that processes all files starting at rootPath, all subdirectories will also be processed
        for root, dirs, files in os.walk(utils.gl_args.input_directory):
            for file in files:

                print('----------------------------------------------------')
                print('Parsing file: ' + file)
                logging.info('Parsing file: ' + file)
                pcap_file = sniff(offline=root + '/' + file, prn=utils.packet_handler(output_file), store=0)
                logging.info('File completed: ' + file)
                print('File completed: ' + file)
                print('----------------------------------------------------')

        logging.info('Directory Parsing Completed: ' + utils.gl_args.input_directory + '/')
        print('Directory Parsing Completed: ' + utils.gl_args.input_directory + '/')

    output_file.writerClose()

    print("Program End")


# Use this for scapy async sniffer
#sniffer = AsyncSniffer(offline=utils.gl_args.input_file, prn=utils.packet_handler(), store=0)
#sniffer.start()
#sniffer.join()