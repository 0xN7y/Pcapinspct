#date 




from scapy.all import *
from scapy.utils import PcapWriter
import datetime
import sys
import time
import os
import random




count = 1                                                                                                                                                                                       
for i in range(6):                                                                                                                                                                              
        try:                                                                                                                                                                                    
                sys.argv[int(i)]                                                                                                                                                                
        except IndexError:                                                                                                                                                                      
                break                                                                                                                                                                           
        count = count + 1 

inp = count -2


help_ = """
\r Usage is very human just\n
\r python3 ./a.py pcap_file [arg]


\r help \t\t\t\t Display help
\r rplsip [old_ip] [new_new] \t Replace ip addrace from every packet  
\r rplsmac [old_mac] [new_mac] \t Replace mac addrace from every packet
\r rmport 3306 \t\t\t Remove every packet conatining certain port
\r rmhttp \t\t\t Remove every packet containing http packet 
\r dnsq \t\t\t Dump all DNS quary from every packet
\r wifi \t\t\t Get info out of packet from packet
\r smtp \t\t\t  Dump all SMTP data from packets
\r telnet\t\t\t Dump all TELNET from every packet 
\r ftp \t\t\t Dump all FTP data from every packet
\r http \t\t\t Dump all HTTP data from every packet
\r prt \t\t\t Dump all used port
\r ips \t\t\t Dump all ip conversation from every packet 
\r macs \t\t\t Dump all mac addr  

"""
empty = """ 
    \r \r  Inspect and manipulate Packets 
\t\t\t Auther: N7y
"""
n7y = """
[...     [..                   
[. [..   [..[..... [..         
[.. [..  [..      [.. [..   [..
[..  [.. [..     [..   [.. [.. 
[..   [. [..    [..      [...  
[..    [. ..    [..       [..  
[..      [..    [..      [..   
                       [..  



    """

if len(sys.argv) == 1:

    for i in empty:
        print(i,end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01,0.0353))
    print(n7y)
    print(help_)
    exit()
if inp == 1:
    if sys.argv[1] == 'help':
        print(help_)
        exit()
    else:

        for i in empty:
            print(i,end="")
            sys.stdout.flush()
            time.sleep(random.uniform(0.01,0.0353))
        print(n7y)
        exit()


q = "0xA"
arg1 = "0x80"
arg2 = "0xN7y"

if inp == 2:
    pcap = sys.argv[1]
    q = sys.argv[2]

if inp == 3:
    pcap = sys.argv[1]
    q = sys.argv[2]
    arg1 = sys.argv[3] 

if inp == 4:
    pcap = sys.argv[1]
    q = sys.argv[2]
    arg1 = sys.argv[3]
    arg2 = sys.argv[4] 


def ipformat(ip):
        try:
            if len(ip.split('.')) == 4:
                return True
            else:
                return False
        except:
            return False

def macformat(mac):
        try:
            if len(mac.split(':')) == 6:
                return True
            else:
                return False
        except:
            return False





# pcap = './AoC3.pcap'
# pcap = '/home/naty/Desktop/shake-01.cap'
if os.path.isfile(pcap):
    for i in "Pcap found!... \n":
        print(i,end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01,0.0353))
else:
    c = 0
    for i in "Pcap Not found!...       u mf \n quiting... \n":
        print(i,end="")
        sys.stdout.flush()
        if c ==18:
            time.sleep(1)
        time.sleep(random.uniform(0.01,0.0353))
        c = c + 1
    exit()

p = rdpcap(pcap)




ips_conv = []
macs_conv = []
prts = []
dnsq = []
http = []
ftp = []
ssh = []
telnet = []
smtp = []
snmp = []
wifi = []
notf = "Not Found !"

if q == "ips":
    for i in "[ips] ... Dumping all ip conversation from every packet \n":
        print(i,end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01,0.0353))

    for packets in p:
        if IP in packets:
            mv = packets[IP].src +' - >'+  packets[IP].dst
            ips_conv.append(mv)
        else:
            if len(ips_conv) == 0:

                ips_conv.append("Not Found !")


    uiq_ip = []

    for new in ips_conv:
        if new not in uiq_ip:
            uiq_ip.append(new)
    ips_conv=uiq_ip

    for i in ips_conv:
        print('\t',i)



if q == 'macs':
    for i in "[macs] ... Dumping all mac addr \n":
        print(i,end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01,0.0353))
    for packets in p:
        if Ether in packets:
            mv = packets[Ether].src +' -> '+ packets[Ether].dst
            macs_conv.append(mv)
        else:
            if len(macs_conv) == 0:

                macs_conv.append("Not Found !")
    uiq_macs_conv = []


    for n in macs_conv :
        if n not in uiq_macs_conv:
            uiq_macs_conv.append(n)
    macs_conv = uiq_macs_conv

    for i in macs_conv:
        print('\t',i)



if q == 'prt':
    for i in "[prt] ... Found some port not all \n ":
        print(i,end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01,0.0353))
    for packets in p:
        cln = []
        if TCP in packets:
            if packets[TCP].sport not in cln:
                cln.append(packets[TCP].sport)

            if packets[TCP].dport not in cln:
                cln.append(packets[TCP].dport)
        else:
            cln.append("Not Found !")
        prts = cln
    for i in prts:
        print('\t',i)



if q == 'dnsq':
    for i in "[dnsq] ... Dump all DNS quary from every packet \n ":
        print(i,end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01,0.0353))
    for packets in p:
        
        if DNSQR in packets:
            dnsq.append(packets[DNSQR].qname.decode())
        else:
            dnsq.append("NOt Found !")
    cln_dns = []
    for n in dnsq:
        if n not in cln_dns:
            cln_dns.append(n)
    dnsq = cln_dns    
    for i in dnsq:
        print('\t',i)  



if q == 'http':
    for i in "[http] ... Dump all HTTP data from every packet \n ":
        print(i,end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01,0.0353))
    for packets in p:
        if packets.haslayer(TCP) and packets.haslayer(Raw):
            if packets[TCP].dport == 80 or packets[TCP].sport == 80:
                # print(packets[Raw].load.decode('utf-8', errors='ignore'))
                http_ = packets[Raw].load.decode('utf-8', errors='ignore')
                if 'HTTP' in http_:
                    http.append(http_)
                else:
                    if len(http) == 0:

                        http.append(notf)
    for i in http:
        print(i)



if q == 'ftp':
    for i in "[ftp] ... Dump all ftp data from packet \n ":
        print(i,end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01,0.0353))
    for packets in p:
            if packets.haslayer(TCP) and packets.haslayer(Raw):
                if packets[TCP].dport == 21 or packets[TCP].sport == 21:
                    ftp.append(packets[Raw].load.decode())
                else:
                    if len(ftp) == 0:

                        ftp.append(notf)
    for i in ftp:
        print('\t',i)


if q == ssh:
    for i in "[ssh] ... Dump all ssh data from packet \n ":
        print(i,end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01,0.0353))
    for packets in p:
            if packets.haslayer(TCP) and packets.haslayer(Raw):
                if packets[TCP].dport == 22 or packets[TCP].sport == 22:
                    ssh.append(packets[Raw].load.decode('utf-8', errors='ignore'))
                else:
                    if len(ssh) == 0:
                        ssh.append(notf)
    for i in ssh:
        print(i)


if q == 'telnet':
    for i in "[telnet] ... Sucking  TELNET out from from packet \n ":
        print(i,end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01,0.0353))
    for packets in p:
            if packets.haslayer(TCP) and packets.haslayer(Raw):
                if packets[TCP].dport == 23 or packets[TCP].sport == 23:
                    telnet.append(packets[Raw].load.decode())
                else:
                    if len(telnet) == 0 :

                        telnet.append(notf)
    for i in telnet:
        print('\t',i)


if q == 'smpt':
    for i in "[smpt] ... Dumping  SMTP out of packet \n ":
        print(i,end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01,0.0353))
    for packets in p:
            if packets.haslayer(TCP) and packets.haslayer(Raw):
                if packets[TCP].dport == 25 or packets[TCP].sport == 25:
                    smtp.append(packets[Raw].load.decode())
                else:
                    if len(smtp) == 0 :

                        smtp.append(notf)

    for i in smtp:
        print(i)


if q == 'wifi':
    for i in "[wifi] ... Dumping  wifi data out of packets \n ":
        print(i,end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01,0.0353))
    for packet in p:
        if packet.haslayer(Dot11):
          
            try:
                ssid = packet[Dot11].info.decode()
                print('\t ssid :',ssid)
                bssid = packet[Dot11].addr3
                print('\t bssid : ',bssid)
                addr1 = packet[Dot11].addr1
                print('\t addr1: ',addr1)
                addr2 = packet[Dot11].addr2
                print('\t addr2 : ',addr2)
                cap = packet[Dot11Beacon].cap
                print('\t Capablities: ',cap)
             
                timestamp = datetime.datetime.fromtimestamp(packet[Dot11].timestamp).strftime("%A, %B %d, %Y %I:%M:%S")
                print('\t Time: ',timestamp)
                # print(packet.show) 
                
                break
            except:
                
                pass

if q == "rplsip":
    for i in "[rplsip] ... Replace ip addrace from every packet  \n ":
            print(i,end="")
            sys.stdout.flush()
            time.sleep(random.uniform(0.01,0.0353))
    if ipformat(arg1) and ipformat(arg2):
        old_new_info = "[] Replacing "+arg1+" With "+arg2+"\n"
        for i in old_new_info:
            print(i,end="")
            sys.stdout.flush()
            time.sleep(random.uniform(0.01,0.0353))
        def rplsip(old,new):
            output_pcap = '_iprp_' +pcap.split('/')[-1]
            for packet in p:
                if IP in packet:

                    if packet[IP].src == old:
                        packet[IP].src = new
                  
                    if packet[IP].dst == old:

                        packet[IP].dst = new
                   
                        


            
            wrpcap(output_pcap, p)
        rplsip(arg1,arg2)    
        for i in "[rplsip] ... outputing file \n Done \n ":
            print(i,end="")
            sys.stdout.flush()
            time.sleep(random.uniform(0.01,0.0353))
    else:
        c = 0
        for i in "invalid ip format!...     u mf \n quiting... \n":
            print(i,end="")
            sys.stdout.flush()
            if c ==18:
                time.sleep(1)
            time.sleep(random.uniform(0.01,0.0353))
            c = c + 1



if q == "rplsmac":
    for i in "[rplsmac] ... Replacing MACS addrace from every packets \n ":
            print(i,end="")
            sys.stdout.flush()
            time.sleep(random.uniform(0.01,0.0353))    

    if macformat(arg1) and macformat(arg2):
        old_new_info = "[] subsituuuing "+arg1+" With "+arg2+"\n"
        for i in old_new_info:
            print(i,end="")
            sys.stdout.flush()
            time.sleep(random.uniform(0.01,0.0353))

        def rplsmac(old,new):
            output_pcap = '_macrp_' +pcap.split('/')[-1]
            for packet in p:

                if Ether in packet:
                    if packet[Ether].src == old:
                        packet[Ether].src = new
                    
                        

                    if packet[Ether].dst == old:
                        packet[Ether].dst = new
    
                
                    
          
            wrpcap(output_pcap, p)
        rplsmac(arg1,arg2)
        for i in "[rplsmac] ... outputing file \n Done \n ":
            print(i,end="")
            sys.stdout.flush()
            time.sleep(random.uniform(0.01,0.0353))
    else:
        c = 0
        for i in "invalid mac format!...     u mf \n quiting... \n":
            print(i,end="")
            sys.stdout.flush()
            if c ==18:
                time.sleep(1)
            time.sleep(random.uniform(0.01,0.0353))
            c = c + 1




if q == 'rmhttp':
    for i in "[rmhttp] ... Removing http containing packet \n ":
        print(i,end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01,0.0353))
    def rmhttp():
        output_pcap = '_rmhttp_' +pcap.split('/')[-1]
        filterd_p = []
        for packet in p:
            if packet.haslayer(TCP) and packet.haslayer(Raw):

                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    http_ = packet[Raw].load.decode('utf-8', errors='ignore')
                    if 'HTTP' in http_:
                        del packet[Raw]

            filterd_p.append(packet)

        wrpcap(output_pcap, filterd_p)
        for i in "[rmhttp] ... outputing file \n Done \n ":
            print(i,end="")
            sys.stdout.flush()
            time.sleep(random.uniform(0.01,0.0353))
    rmhttp()
    print("Done")


if q == 'rmprt':
    arg1 = str(arg1)
    if arg1.isnumeric():
        for i in "[rmprt] ... Removing port from packet \n ":
            print(i,end="")
            sys.stdout.flush()
            time.sleep(random.uniform(0.01,0.0353))
        def rmprt(prt):
            prt = int(prt)
            filterd_p = []
            output_pcap = '_rm'+str(prt)+"_"+ pcap.split('/')[-1]

            for packet in p:
                if packet.haslayer(TCP) and packet[TCP].dport == prt:
                    del packet[TCP]
                if packet.haslayer(TCP) and packet[TCP].sport == prt:
                    del packet[TCP]
                if packet.haslayer(UDP) and packet[UDP].dport == prt:
                    del packet[TCP]
                if packet.haslayer(UDP) and packet[UDP].sport == prt:
                    del packet[TCP]
                filterd_p.append(packet)

            wrpcap(output_pcap, filterd_p)
            for i in "[rmprt] ... outputing file \n Done \n ":
                print(i,end="")
                sys.stdout.flush()
                time.sleep(random.uniform(0.01,0.0353))

        rmprt(arg1)

    else:
        c = 0
        for i in "invalid port!...     u mf \n quiting... \n":
            print(i,end="")
            sys.stdout.flush()
            if c ==18:
                time.sleep(1)
            time.sleep(random.uniform(0.01,0.0353))
            c = c + 1





# rmprt(3389)
# rmhttp()
# rplsmac('08:00:27:43:73:bc','00:00:00:00:00:00')
# rplsip('10.10.10.5', '0.0.0.0')
# print(ips_conv)
# print(macs_conv)
# print(prts)
# print(dnsq)
#print(http)
# print(ftp)
# print(ssh)
# print(telnet)
