from scapy.all import *
import utils


class Sniffer:

    sniffers = []

    def start_sniffer(self, filename):

        num_packets = len(rdpcap(filename))
        sniffer = AsyncSniffer(offline=filename, prn=utils.packet_handler(num_packets), store=0)
        sniffer.kwargs.update({'filename': filename})
        sniffer.start()
        self.sniffers.append(sniffer)

    def join(self):
        for sniffer in self.sniffers:
            logging.info('File completed: ' + sniffer.kwargs['filename'])
            print('File completed: ' + sniffer.kwargs['filename'])
            sniffer.join()

        logging.info('Directory Parsing Completed: ' + utils.gl_args.input_directory + '/')
        print('Directory Parsing Completed: ' + utils.gl_args.input_directory + '/')