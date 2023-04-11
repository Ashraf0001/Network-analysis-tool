import pyshark
import argparse
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def analyze_traffic(interface, duration):
    """
    Analyze network traffic for a specified duration on a given interface
    :param interface: name of the interface to capture traffic on
    :param duration: duration (in seconds) to capture traffic for
    """
    capture = pyshark.LiveCapture(interface=interface)
    logging.info(f"Capturing traffic on interface {interface} for {duration} seconds...")
    capture.sniff(timeout=duration)
    logging.info(f"Traffic capture complete. Total packets captured: {len(capture)}")

    # Analyze packets
    count = 0
    for packet in capture:
        count += 1
        # Check for potential attacks
        if 'tcp' in packet and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
            logging.warning(f"Potential port scanning detected: {packet.ip.src} -> {packet.ip.dst}")
        if 'tcp' in packet and packet.tcp.flags_rst == '1':
            logging.warning(f"Potential DoS attack detected: {packet.ip.src} -> {packet.ip.dst}")
        if 'http' in packet and 'authorization' in str(packet.http).lower():
            logging.warning(f"Potential brute force attack detected: {packet.ip.src} -> {packet.ip.dst}")
    logging.info(f"Total potential attacks detected: {count}")

if __name__ == '__main__':
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Network Traffic Analysis Tool')
    parser.add_argument('--interface', dest='interface', required=True, help='name of the interface to capture traffic on')
    parser.add_argument('--duration', dest='duration', type=int, required=True, help='duration (in seconds) to capture traffic for')
    args = parser.parse_args()

    analyze_traffic(args.interface, args.duration)
