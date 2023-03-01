# NetworkScanner

This program uses the `pcap` library to capture TCP packets on the `eth0` network interface and print information about each packet to the console.

## Installation

To compile the program, you will need to install the `libpcap-dev` package:

sudo apt-get install libpcap-dev


Then, compile the program using the `gcc` compiler:

gcc -o sniffer sniffer.c -lpcap


## Usage

To run the program, simply execute the compiled binary:

./sniffer


The program will start capturing packets and printing information about each packet to the console. To stop the program, press `Ctrl+C`.

## How it Works

1. The program initializes the `pcap` library by calling `pcap_open_live`. This function opens a network interface for capturing packets. In this case, the `eth0` interface is used.

2. The program compiles a filter expression using `pcap_compile`. The filter expression `"tcp"` is used to capture only TCP packets. The compiled filter is then applied to the network interface using `pcap_setfilter`.

3. The program starts capturing packets using `pcap_loop`. The `packet_handler` function is called for each captured packet.

4. In the `packet_handler` function, the program extracts the Ethernet, IP, and TCP headers from the packet data. It checks whether the packet is an IP packet by checking the Ethernet type field, and whether it is a TCP packet by checking the IP protocol field.

5. If the packet is a TCP packet, the program prints the source and destination IP addresses and port numbers to the console using `printf`.

6. The program continues to capture packets until it is interrupted.

Overall, the program captures TCP packets on the `eth0` interface and prints information about each packet to the console. This can be useful for network monitoring and analysis.


Description:
The program initializes the pcap library by calling pcap_open_live. This function opens a network interface for capturing packets. In this case, the eth0 interface is used.

The program compiles a filter expression using pcap_compile. The filter expression "tcp" is used to capture only TCP packets. The compiled filter is then applied to the network interface using pcap_setfilter.

The program starts capturing packets using pcap_loop. The packet_handler function is called for each captured packet.

In the packet_handler function, the program extracts the Ethernet, IP, and TCP headers from the packet data. It checks whether the packet is an IP packet by checking the Ethernet type field, and whether it is a TCP packet by checking the IP protocol field.

If the packet is a TCP packet, the program prints the source and destination IP addresses and port numbers to the console using printf.

The program continues to capture packets until it is interrupted.

Overall, the program captures TCP packets on the eth0 interface and prints information about each packet to the console. This can be useful for network monitoring and analysis.
