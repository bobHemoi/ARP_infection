#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include "mac.h"
#include "ip.h"
#include <arpa/inet.h>

Mac my_mac_addr();
Ip my_ip_addr();