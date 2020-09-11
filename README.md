# TCP-RST-VideoStreaming-Attack

This repository contains the design and implementation (in ``C`` and ``Python``) of TCP reset attack on video streaming applications. It has been tested to perform on a LAN (Local Area Network).

This attack was performed in Ubuntu, a Linux distribution.  You need to install ``pcap`` and ``scapy`` prior to performing the attack. 

To install ``pcap``, run the following commands:

```
sudo apt-get update -y 
sudo apt-get install -y libpcap-dev
 ```
 
 To install ``scapy``, run the following commands:
 
 ```
 sudo apt-get update -y
 sudo apt-get install -y scapy
 ```

Firstly, we need to perform Man in the Middle (MITM) attack to be able to sniff packets from the victim. Afterwards, we will start sending TCP RST packets to the victim to disrupt the video stream.

1.If server is outside the subnet, enable attacker to sniff all packets between the network gateway and the victim : 

```
python MITM.py victim_ip
```

2.If server is within the same subnet, enable attacker to sniff all packets between the server and the victim: 

```
python MITM.py victim_ip server_ip
```

3.Enable IP forwarding on attacker machine by typing the following command: 

```
sudo sysctl -w net.ipv4.ip_forward=1
```

4.Compile and run the program on attacker machine to start TCP RST attack:

```
gcc sniff_spoof.c -lpcap
sudo ./a.out
```

Documentation folder contains the design, diagrams, implementation, screenshots and the final report.