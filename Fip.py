from scapy.all import *
from random import randint
import sys,logging
def main():
    # waring is not let me see
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    count = 0
    j=0
    ip = input("give me you network segment  (like 192.168.159. ):")

    ip_li=[]
    #ip list
    for i in range(1,255):
        i = str(i)
        ip_li.append( ip+i)
        j = j + 1

    for i in ip_li :
        # send icmp packet
        packet = IP(dst=i)/ICMP()
        ans,unans = sr(packet,timeout=1,verbose=False)
        try:
            for snd,rcv in ans:
                print(rcv.sprintf('%IP.src% is alive'))
        except:
            count = count+1
    print('%d is lose'%(count))
if __name__ == '__main__':
    main()