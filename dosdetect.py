from scapy.all import *
from difflib import SequenceMatcher
from ipaddress import IPv4Address, IPv4Network
import iptc


def blacklistIP(captured_pkts):
	if(len(captured_pkts[ICMP][0])>200):
		ip_addr = captured_pkts[0][IP].src.split(".")[0]+"."+captured_pkts[0][IP].src.split(".")[1]+"."+captured_pkts[0][IP].src.split(".")[2]+".0/24"
		BL=open("blacklist.txt","a+")
		BL.seek(0)
		blacklist=BL.readlines()
		if((ip_addr+"\n") in blacklist):
			BL.seek(0)
		else:
			BL.write(ip_addr+"\n")	
			rule=iptc.Rule()
			rule.in_interface="enp0s3"
			rule.src=ip_addr
			rule.protocol="icmp"
			rule.create_match("icmp")
			rule.create_target("DROP")
			chain = iptc.Chain(iptc.Table(iptc.Table.FILTER),"INPUT")
			chain.insert_rule(rule)
			BL.seek(0)
		BL.seek(0)
		BL.close()		

captured_pkts = sniff(filter="icmp[icmptype]!=icmp-echoreply or tcp[tcpflags] & tcp-syn!=0", prn=blacklistIP,timeout=20)
print("\nShowing last captured packet IP\n")
lastpkt =int(len(captured_pkts[ICMP])-1)
captured_pkts[ICMP][lastpkt].show()
