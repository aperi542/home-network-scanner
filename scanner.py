import scapy.all as scapy
from mac_vendor_lookup import MacLookup

def get_vendor(mac_address):
    """Look up the vendor/manufacturer from MAC address"""
    try:
        mac = MacLookup()
        vendor = mac.lookup(mac_address)
        return vendor
    except:
        return "Unknown"

def categorize_device(vendor):
    """Categorize device based on vendor name"""
    vendor_lower = vendor.lower()
    
    # Mobile devices
    if any(x in vendor_lower for x in ['apple', 'samsung', 'google', 'huawei', 'xiaomi', 'oneplus', 'motorola', 'lg electronics']):
        return "Mobile"
    
    # Computers
    elif any(x in vendor_lower for x in ['intel', 'dell', 'hp', 'lenovo', 'asus', 'acer', 'microsoft']):
        return "Computer"
    
    # IoT devices
    elif any(x in vendor_lower for x in ['amazon', 'ring', 'nest', 'philips', 'tp-link', 'belkin', 'sonos', 'roku', 'ecobee', 'wyze', 'dreame', 'xiaomi', 'tuya']):
        return "IoT"
    
    # Networking equipment
    elif any(x in vendor_lower for x in ['netgear', 'cisco', 'linksys', 'ubiquiti', 'aruba']):
        return "Router/Network"
    
    # Entertainment
    elif any(x in vendor_lower for x in ['sony', 'nintendo', 'roku', 'vizio', 'lg electronics']):
        return "Entertainment"
    
    else:
        return "Unknown"

def scan_network(ip_range):
    """Scan the network and return list of devices with vendor and category"""
    print(f"Scanning network {ip_range}...")
    
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        vendor = get_vendor(element[1].hwsrc)
        category = categorize_device(vendor)
        
        device_info = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
            "vendor": vendor,
            "category": category
        }
        devices.append(device_info)
    
    return devices

def print_summary(devices):
    """Print a network security summary"""
    print("\n" + "="*70)
    print("NETWORK SECURITY SNAPSHOT")
    print("="*70)
    
    # Count by category
    categories = {}
    for device in devices:
        cat = device['category']
        categories[cat] = categories.get(cat, 0) + 1
    
    print(f"\nTotal Devices: {len(devices)}")
    print("\nDevice Breakdown:")
    for category, count in sorted(categories.items()):
        print(f"  {category}: {count}")
    
    # Security notes
    print("\nSecurity Notes:")
    iot_count = categories.get('IoT', 0)
    unknown_count = categories.get('Unknown', 0)
    
    if iot_count > 3:
        print(f"  ⚠️  High number of IoT devices ({iot_count}) - ensure they're updated regularly")
    if unknown_count > 0:
        print(f"  ⚠️  {unknown_count} unknown device(s) detected - review manually")
    if iot_count == 0 and unknown_count == 0:
        print("  ✓ Network appears normal")
    
    print("="*70)

if __name__ == "__main__":
    ip_range = "10.0.5.0/24"
    
    devices = scan_network(ip_range)
    
    print("\n" + "="*70)
    print("DEVICES FOUND ON NETWORK")
    print("="*70)
    
    for i, device in enumerate(devices, 1):
        print(f"\nDevice {i}:")
        print(f"  IP Address:  {device['ip']}")
        print(f"  MAC Address: {device['mac']}")
        print(f"  Vendor:      {device['vendor']}")
        print(f"  Category:    {device['category']}")
    
    print_summary(devices)
