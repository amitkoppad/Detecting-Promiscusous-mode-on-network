# Detecting-Promiscusous-mode-on-network
This program detects systems using promiscuous mode on the network.
The program uses a kernel vulnerability that is present on the linux systems. When there is a broadcast message on the network the kernel
only checks for the first octet of the MAC address. If the first octet is ff the kernel considers this as a broadcast message. 
Now when the promiscuos mode is enabled on the systems, only kernel is filtering/checking the MAC address. So in this program we construct a 
packet with sudo MAC address which has the first octet as ff. When this packet is sent out to every system on the network, the systems not using 
promiscuous mode do not reply to this packet as the NIC card discards the packet. But if we get a reply for this packet from any system we
can conclude that the system is using promiscuous mode or Wireshark or any other packet sniffer.
