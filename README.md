# Home Network Scanner

A Python-based network visibility tool that identifies and categorizes devices on a local network, providing security-focused insights for home network awareness.

## Overview

This project scans a local Wi-Fi network to discover connected devices, identifies their manufacturers using MAC address lookup, and categorizes them into logical groups (computers, IoT devices, mobile devices, etc.). It then generates a security snapshot highlighting potential areas of concern.

## Motivation

As IoT devices become increasingly common in homes, understanding what's connected to your network is the first step in maintaining security.

## Features

- Network Scanning: Discovers all active devices on the local network using ARP requests
- Vendor Identification: Uses MAC address prefixes to identify device manufacturers
- Device Categorization: Automatically groups devices into categories:
  - Computers
  - IoT Devices
  - Mobile Devices
  - Entertainment Systems
  - Network Equipment
  - Unknown
- Security Snapshot: Provides basic security insights:
  - Flags high numbers of IoT devices
  - Identifies unknown devices for manual review
  - Summary statistics

## Technical Implementation

Language: Python 3  
Key Libraries:
- `scapy` - Network packet manipulation and ARP scanning
- `mac-vendor-lookup` - MAC address to vendor mapping

How it works:
1. Sends ARP (Address Resolution Protocol) requests to all IPs in the specified range
2. Collects responses containing IP and MAC addresses
3. Looks up vendor information using the MAC address OUI (first 6 characters)
4. Categorizes devices based on vendor patterns
5. Generates formatted output with security insights

## Requirements

- Python 3.7+
- Root/administrator privileges (required for network scanning)
- Mac/Linux system (Windows requires additional setup)

## Installation
```bash
# Clone the repository
git clone https://github.com/aperi542/home-network-scanner.git
cd home-network-scanner

# Install dependencies
pip3 install -r requirements.txt
```

## Usage

1. **Find your network range**: Most home networks use `192.168.1.0/24` or `192.168.0.0/24`

2. **Edit scanner.py** to match your network (line 77):
```python
ip_range = "192.168.1.0/24"  # Change this to your network
```

3. **Run the scanner**:
```bash
sudo python3 scanner.py
```

## Example Output
```
Scanning network 10.0.5.0/24...

======================================================================
DEVICES FOUND ON NETWORK
======================================================================

Device 1:
  IP Address:  10.0.5.1
  MAC Address: aa:bb:cc:dd:ee:ff
  Vendor:      Netgear
  Category:    Router/Network

Device 2:
  IP Address:  10.0.5.23
  MAC Address: cc:9e:a2:a6:80:35
  Vendor:      Amazon Technologies Inc.
  Category:    IoT

======================================================================
NETWORK SECURITY SNAPSHOT
======================================================================

Total Devices: 6

Device Breakdown:
  Computer: 1
  IoT: 3
  Router/Network: 1
  Unknown: 1

Security Notes:
  ⚠️  1 unknown device(s) detected - review manually
======================================================================
```

## Project Context

This project was completed as a self-directed learning initiative to deepen my understanding of networking, cybersecurity, and practical software development. It demonstrates the intersection of computer engineering concepts (hardware identification, network protocols) with security awareness.

## License

MIT License - Feel free to use and modify for educational purposes.

## Acknowledgments

This project was developed with assistance from Claude (Anthropic) for guidance on Python implementation and networking concepts.

## Contact

GitHub: [@aperi542](https://github.com/aperi542)
