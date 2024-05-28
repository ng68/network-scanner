# network-scanner
Personal cybersecurity project: Network Scanner

Functions:

- ARP Scan - Sends ARP requests all devices on your local network.
- TCP Scan - Performs a TCP scan by sending SYN packets to a list of ports you give it.
- Local IP Scan - Provides a list of all local IPs being used

Instructions:

Run: `python scanner.py [Arg1]`

`Arg1: 
    ScanType (string): ARP, TCP, or IP`


ARP Scan Arg:
```
MaskLength (int): The length of the subnet mask of your local network

Returns:
    A list of dictionaries mapping IP addresses to MAC addresses. For example:
    [
        {'IP': '192.168.0.1', 'MAC': 'a1:b2:c3:d4:e5:f6'}
    ]
```
TCP Scan Args:
```
      ip (str): An IP address or hostname to target.
      ports (list or tuple of int): A list or tuple of ports to scan.

    Returns:
        A list of ports that are open.
```
IP Scan Args:
```
    MaskLength (int): The length of the subnet mask of your local network. (ie. 16, 24, and 32)

    Returns:
        A list of IP addresses being used on your local network.
```
