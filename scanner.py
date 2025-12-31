import scapy.all as scapy
from mac_vendor_lookup import MacLookup

def get_vendor(mac_address):
    """
    Look up the vendor/manufacturer from MAC address
    """
    try:
        mac = MacLookup()
        vendor = mac.lookup(mac_address)
        return vendor
    except:
        return "Unknown"

def scan_network(ip_range):
    """
    Scan the network and return list of devices with vendor info
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
        # Get vendor information
        vendor = get_vendor(element[1].hwsrc)
        
        device_info = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
            "vendor": vendor
        }
        devices.append(device_info)
    
    return devices

if __name__ == "__main__":
    # Change this to match YOUR network
    ip_range = "10.0.5.0/24"
    
    devices = scan_network(ip_range)
    
    print("\n" + "="*60)
    print("DEVICES FOUND ON NETWORK")
    print("="*60)
    
    for i, device in enumerate(devices, 1):
        print(f"\nDevice {i}:")
        print(f"  IP Address:  {device['ip']}")
        print(f"  MAC Address: {device['mac']}")
        print(f"  Vendor:      {device['vendor']}")
    
    print("\n" + "="*60)
    print(f"Total devices found: {len(devices)}")
    print("="*60)
