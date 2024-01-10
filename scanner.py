import argparse
import socket
from scapy.all import *

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('255.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def arp_scan(net):
    """
    Performs a network scan by sending ARP requests all devices on your local network.

    Args:
        MaskLength (int): The length of the subnet mask of your local network

    Returns:
        A list of dictionaries mapping IP addresses to MAC addresses. For example:
        [
            {'IP': '192.168.0.1', 'MAC': 'a1:b2:c3:d4:e5:f6'}
        ]
    """
    

    #Send ARP requests to local IPs
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net)

    ans, unans = srp(request, timeout=2, retry=1)
    result = []

    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})

    return result


def tcp_scan(ip, ports):
    """
    Performs a TCP scan by sending SYN packets to <ports>.

    Args:
        ip (str): An IP address or hostname to target.
        ports (list or tuple of int): A list or tuple of ports to scan.

    Returns:
        A list of ports that are open.
    """
    try:
        syn = IP(dst=ip) / TCP(dport=ports, flags="S")
    except socket.gaierror:
        raise ValueError('Hostname {} could not be resolved.'.format(ip))

    ans, unans = sr(syn, timeout=2, retry=1)
    result = []

    for sent, received in ans:
        if received[TCP].flags == "SA":
            result.append(received[TCP].sport)

    return result

def ip_scan(net):
    """
    Performs a network scan of all local IPs being used

    Args:
        MaskLength (int): The length of the subnet mask of your local network

    Returns:
        A list of IP addresses being used on your local network.
    """
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net)

    ans, unans = srp(request, timeout=2, retry=1)
    result = []

    for sent, received in ans:
        result.append({'IP': received.psrc})

    return result

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(
        dest="command", help="Command to perform.", required=True
    )

    arp_subparser = subparsers.add_parser(
        'ARP', help='Perform a network scan using ARP requests.'
    )
    arp_subparser.add_argument(
        'MaskLength', help='The length of the Subnet mask of your local network'
    )

    tcp_subparser = subparsers.add_parser(
        'TCP', help='Perform a TCP scan using SYN packets.'
    )
    tcp_subparser.add_argument('IP', help='An IP address or hostname to target.')
    tcp_subparser.add_argument(
        'ports', nargs='+', type=int,
        help='Ports to scan, delimited by spaces. When --range is specified, scan a range of ports. Otherwise, scan individual ports.'
    )
    tcp_subparser.add_argument(
        '--range', action='store_true',
        help='Specify a range of ports. When this option is specified, <ports> should be given as <low_port> <high_port>.'
    )
    ip_subparser = subparsers.add_parser(
        'IP', help='Perform a scan of all local IPs being used'
    )
    ip_subparser.add_argument(
        'MaskLength', help='The length of the Subnet mask of your local network'
    )

    args = parser.parse_args()

    if args.command == 'ARP':
        hostip = get_local_ip()
        print("Host IP found: " + hostip)
        mask = str(args.MaskLength)
        result = arp_scan(hostip + "/" + mask)

        for mapping in result:
            print('{} ==> {}'.format(mapping['IP'], mapping['MAC']))

    elif args.command == 'TCP':
        if args.range:
            ports = tuple(args.ports)
        else:
            ports = args.ports
        
        try:
            result = tcp_scan(args.IP, ports)
        except ValueError as error:
            print(error)
            exit(1)

        for port in result:
            print('Port {} is open.'.format(port))

    elif args.command == 'IP':
        hostip = get_local_ip()
        print("Host IP found: " + hostip)
        mask = str(args.MaskLength)
        result = ip_scan(hostip + "/" + mask)

        for mapping in result:
            print("IP: " + mapping['IP'])

if __name__ == '__main__':
    main()
