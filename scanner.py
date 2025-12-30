import scapy.all as scapy

def scan_network(ip_range):
    """
    Scan the network and return list of devices
    ip_range: something like "192.168.1.0/24"
    """
    print(f"Scanning network {ip_range}...")
    
    # Create an ARP request to find devices
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    # Send the request and get responses
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        device_info = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }
        devices.append(device_info)
    
    return devices

if __name__ == "__main__":
    # You'll need to change this to match YOUR network
    # Most home networks use 192.168.1.0/24 or 192.168.0.0/24
    ip_range = "10.0.5.0/24"
    
    devices = scan_network(ip_range)
    
    print("\nDevices found:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

