import sys
import logging
from scapy.all import *
import pandas as pd
from tabulate import tabulate
from tqdm import tqdm
from colorama import Fore, Style
import matplotlib.pyplot as plt

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def read_pcap(pcap_file):
    """Read PCAP file and return packets."""
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        logger.error(f"{Fore.RED}PCAP file not found: {pcap_file}{Style.RESET_ALL}")
        sys.exit(1)
    except Scapy_Exception as e:
        logger.error(f"{Fore.RED}Error reading PCAP file: {e}{Style.RESET_ALL}")
        sys.exit(1)
    return packets

def extract_packet_data(packets):
    """Extract relevant packet data."""
    packet_data = []
    for packet in tqdm(packets, desc="Processing packets", unit="packet"):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            size = len(packet)
            packet_data.append({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "size": size})
    df = pd.DataFrame(packet_data)
    
    # Ensure 'Source IP' and 'Destination IP' columns are present
    if 'src_ip' not in df.columns or 'dst_ip' not in df.columns:
        logger.error(f"{Fore.RED}Source IP or Destination IP columns not found in DataFrame.{Style.RESET_ALL}")
        sys.exit(1)
    
    return df


def protocol_name(number):
    """Map protocol number to protocol name."""
    protocol_dict = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    return protocol_dict.get(number, f"Unknown({number})")

def analyze_packet_data(df):
    """Analyze packet data."""
    total_bandwidth = df["size"].sum()
    protocol_counts = df["protocol"].value_counts(normalize=True) * 100
    protocol_counts.index = protocol_counts.index.map(protocol_name)

    # Ensure 'Source IP' and 'Destination IP' columns are present in ip_communication_table
    if 'src_ip' not in df.columns or 'dst_ip' not in df.columns:
        logger.error(f"{Fore.RED}Source IP or Destination IP columns not found in DataFrame.{Style.RESET_ALL}")
        sys.exit(1)

    ip_communication = df.groupby(["src_ip", "dst_ip"]).size().sort_values(ascending=False)
    ip_communication_percentage = ip_communication / ip_communication.sum() * 100
    ip_communication_table = pd.concat([ip_communication, ip_communication_percentage], axis=1).reset_index()
    ip_communication_table.columns = ["Source IP", "Destination IP", "Count", "Percentage"]

    protocol_frequency = df["protocol"].value_counts()
    protocol_frequency.index = protocol_frequency.index.map(protocol_name)

    protocol_counts_df = pd.concat([protocol_frequency, protocol_counts], axis=1).reset_index()
    protocol_counts_df.columns = ["Protocol", "Count", "Percentage"]

    ip_communication_protocols = df.groupby(["src_ip", "dst_ip", "protocol"]).size().reset_index()
    ip_communication_protocols.columns = ["Source IP", "Destination IP", "Protocol", "Count"]
    ip_communication_protocols["Protocol"] = ip_communication_protocols["Protocol"].apply(protocol_name)
    ip_communication_protocols["Percentage"] = ip_communication_protocols.groupby(["Source IP", "Destination IP"])["Count"].apply(lambda x: x / x.sum() * 100).reset_index(drop=True)

    return total_bandwidth, protocol_counts_df, ip_communication_table, protocol_frequency, ip_communication_protocols

    return total_bandwidth, protocol_counts_df, ip_communication_table, protocol_frequency, ip_communication_protocols

def detect_port_scanning(df, port_scan_threshold):
    """Detect potential port scanning activity."""
    # Check if 'dst_port' column exists in the DataFrame
    if 'dst_port' in df.columns:
        port_scan_df = df.groupby(['src_ip', 'dst_port']).size().reset_index(name='count')
        unique_ports_per_ip = port_scan_df.groupby('src_ip').size().reset_index(name='unique_ports')
        potential_port_scanners = unique_ports_per_ip[unique_ports_per_ip['unique_ports'] >= port_scan_threshold]
        ip_addresses = potential_port_scanners['src_ip'].unique()
        if len(ip_addresses) > 0:
            logger.warning(f"{Fore.YELLOW}Potential port scanning detected from IP addresses: {', '.join(ip_addresses)}{Style.RESET_ALL}")
    else:
        logger.warning(f"{Fore.YELLOW}The 'dst_port' column is not present in the DataFrame. Port scanning detection skipped.{Style.RESET_ALL}")
        
def print_results(total_bandwidth, protocol_counts_df, ip_communication_table, protocol_frequency, ip_communication_protocols):
    """Print analysis results."""
    if total_bandwidth < 10**9:
        bandwidth_unit = "Mbps"
        total_bandwidth /= 10**6
    else:
        bandwidth_unit = "Gbps"
        total_bandwidth /= 10**9

    logger.info(f"{Fore.GREEN}Total bandwidth used: {total_bandwidth:.2f} {bandwidth_unit}{Style.RESET_ALL}")

    # Plotting Protocol Distribution
    plt.figure(figsize=(10, 6))
    plt.bar(protocol_counts_df['Protocol'], protocol_counts_df['Count'], color='skyblue')
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.title('Protocol Distribution')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # Plotting Top IP Address Communications if columns exist
    if 'Source IP' in ip_communication_table.columns and 'Destination IP' in ip_communication_table.columns:
        plt.figure(figsize=(10, 6))
        top_ip_communication = ip_communication_table.head(10)
        plt.barh(top_ip_communication['Source IP'] + " -> " + top_ip_communication['Destination IP'], top_ip_communication['Count'], color='lightgreen')
        plt.xlabel('Count')
        plt.ylabel('Source IP -> Destination IP')
        plt.title('Top IP Address Communications')
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plt.show()
    else:
        logger.warning(f"{Fore.YELLOW}Unable to plot Top IP Address Communications: Required columns 'Source IP' and 'Destination IP' not found.{Style.RESET_ALL}")

    logger.info(f"{Fore.BLUE}\nShare of each protocol between IPs:{Style.RESET_ALL}\n")
    print(tabulate(ip_communication_protocols, headers=["Source IP", "Destination IP", "Protocol", "Count", "Percentage"], tablefmt="grid", floatfmt=".2f"))


def main(pcap_file, port_scan_threshold):
    """Main function."""
    packets = read_pcap(pcap_file)
    df = extract_packet_data(packets)
    total_bandwidth, protocol_counts, ip_communication_table, protocol_frequency, ip_communication_protocols = analyze_packet_data(df)
    print_results(total_bandwidth, protocol_counts, ip_communication_table, protocol_frequency, ip_communication_protocols)
    detect_port_scanning(df, port_scan_threshold)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        logger.error(f"{Fore.RED}Please provide the path to the PCAP file.{Style.RESET_ALL}")
        sys.exit(1)

    pcap_file = sys.argv[1]
    default_port_scan_threshold = 100

    if len(sys.argv) >= 3:
        try:
            port_scan_threshold = int(sys.argv[2])
        except ValueError:
            logger.error(f"{Fore.RED}Invalid port_scan_threshold value. Using the default value.{Style.RESET_ALL}")
            port_scan_threshold = default_port_scan_threshold
    else:
        port_scan_threshold = default_port_scan_threshold

    main(pcap_file, port_scan_threshold)

