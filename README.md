
# Network Traffic Analysis Tool

## Overview
This Python script is designed to analyze network traffic data stored in PCAP files. It provides insights into various aspects of network communication, including total bandwidth usage, protocol distribution, top IP address communications, and potential port scanning activity.

## Requirements
- Python 3.x
- scapy library (install using `pip install scapy`)
- pandas library (install using `pip install pandas`)
- matplotlib library (install using `pip install matplotlib`)

## Usage
1. Clone or download the repository to your local machine.
2. Ensure Python 3.x is installed on your system.
3. Install required dependencies by running:
   ```
   pip install -r requirements.txt
   ```
4. Open a terminal and navigate to the directory containing the script.
5. Run the script using the following command:
   ```
   python network_traffic_analysis.py path/to/your/pcap/file.pcap [port_scan_threshold]
   ```
   Replace `path/to/your/pcap/file.pcap` with the path to your PCAP file. Optionally, you can specify a port scan threshold (default is 100).
6. The script will analyze the network traffic data and generate a report with the results.

## Command-line Arguments
- `path/to/your/pcap/file.pcap`: Path to the PCAP file containing network traffic data.
- `port_scan_threshold` (optional): Threshold for detecting potential port scanning activity. Default is 100.

## Output
- The script will print analysis results to the console, including total bandwidth usage, protocol distribution, top IP address communications, and potential port scanning activity.
- Additionally, visualizations such as bar charts may be displayed to illustrate protocol distribution and top IP address communications.

## Example
```
python network_traffic_analysis.py example.pcap 50
```
.

