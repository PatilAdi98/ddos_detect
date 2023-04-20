# ddos_detect
Attacker and Defender scripts for DDoS simulation, detection and mitigation assistance
Note: Both scripts were run on Ubuntu 16.04 32-bit Virtual Machines with python3, located in the same network

Pre-requisites-

Both attacker and victim require the Scapy library:
pip install scapy

Victim machine additionally requires python-iptables for creating firewall rules:
pip install python-iptables

Once pre-requisites are setup, run the victim's script with root privileges:
sudo python dosdetect.py 
The timeout is currently set to 20 seconds, so the attacker needs to be run immediately after this
sudo python attacker.py <IP to be spoofed>
The attacker currently sends 100 ping packets with 65000 bytes payload 
  
The victim will run for 20 seconds and you can then check the firewall rules to ensure blacklisting of the source IP
sudo iptables -L

A text file "blacklist.txt" is also generated in the victim to show which IPs are blacklisted
