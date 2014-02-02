/*
 * usurfkill.h
 *
 *  Created on: Jan 21, 2014
 *      Author: Onur
 */

#ifndef USURFKILL_H_
#define USURFKILL_H_

#define CATCH_BUFFER	100
#define LOG_FILE_NAME	"usurf.log"

void catch_ssl_hsk(u_char *args, const struct pcap_pkthdr* pkthdr,
		const u_char* packet);
void send_rst(struct ethernet_header* ether_h, struct ip_header* ip_h,
		struct tcp_header* tcp_h, char* iface_name, int rst_num);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);

typedef struct _callback_opt {
	char** catch_table;
	int catch_num;
	int rst_num;
	char* iface;
	FILE* log_file;
} callback_opt;


#endif /* USURFKILL_H_ */
