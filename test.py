from scapy.all import *
import base64

pcap = "giyh-capture.pcap"
pitcher = "" 
for key, pkts in rdpcap(pcap).sessions().items():
    for pkt in pkts:
        if DNS in pkt:
            if pkt.ancount > 0 and isinstance(pkt.an, DNSRR):
                response = base64.b64decode(pkt.an.rdata.decode('ASCII'))
                if "FILE:" in response:
                    print("%s" % (base64.b64decode(pkt.an.rdata.decode('ASCII'))))
                    pitcher += response.split("FILE:")[1]

#print(pitcher)



