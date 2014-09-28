#ifndef DLSNIFFER_DEFS_H
#define DLSNIFFER_DEFS_H

#define DLSNIFFER_FILTER ("arp or tcp or udp or icmp")

// TCP 协议
#define FTP_PORT 		(21)
#define TELNET_PORT 	(23)
#define SMTP_PORT 		(25)
#define HTTP_PORT  		(80)
#define HTTPS_PORT		(443)
#define POP3_PORT 		(110)
#define IMAP_PORT       (143)

// UDP 协议
#define DNS_PORT		(53)
#define SNMP_PORT		(161)

#endif // DLSNIFFER_DEFS_H
