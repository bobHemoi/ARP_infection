#include "myMacAddr.h"


Mac my_mac_addr(){
    struct ifreq ifr;
	char MAC_str[13];
    char* mac_ptr = MAC_str;

	#define HWADDR_len 6
    int s,i;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, "eth0");
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i<HWADDR_len; i++)
        sprintf(&MAC_str[i*2],"%02X",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
    MAC_str[12]='\0';
    // i = close(s);

    Mac mymac{mac_ptr};
	return mymac;
}

Ip my_ip_addr(){
    struct ifreq ifr;
    char ipstr[40];
    int s;
 
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ);
 
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Error");
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                ipstr,sizeof(struct sockaddr));
        printf("myOwn IP Address is %s\n", ipstr);
        return Ip(ipstr);
    }
}