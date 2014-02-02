/*
 * main.c
 *
 *  Created on: Jan 19, 2014
 *      Author: Onur
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <libnet.h>
#include "tcpip.h"
#include "usurfkill.h"


int main(int argc, char** argv) {

	char* conf_file_name;
	char* pcap_filter;
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct bpf_program compiled_filter;
	pcap_t* ihandle;
	bpf_u_int32 ip_v4, mask_v4;
	callback_opt options;
	FILE* fp;
	int i, poll_time;

	if(argc < 4) {
		printf("Usage: usurfkill iface conf_file reset_number polling_time \"pcap filter\"\n"
				"Ex: ./usurfkill wlan0 usurf.conf 3 100 \"dst port 443\"\n");
		exit(EXIT_SUCCESS);
	}

	//get the arguments
	options.iface = argv[1];
	options.rst_num = atoi(argv[3]);
	conf_file_name = argv[2];
	poll_time = atoi(argv[4]);
	pcap_filter = argv[5];

	//read the config file
	if((fp = fopen(conf_file_name,"r")) == NULL) {
		fprintf(stderr, "Cannot open the file: %s\n", conf_file_name);
	}

	fscanf(fp, "%d", &(options.catch_num));
	options.catch_table = (char**) malloc(sizeof(char*) * options.catch_num);

	for(i = 0; i < options.catch_num; i++) {
		options.catch_table[i] = (char*) malloc(sizeof(char*) * CATCH_BUFFER);
		fscanf(fp, "%s", options.catch_table[i]);
		//printf("%s\n", options.catch_table[i]);
	}

	fclose(fp);
	printf("Configuration file has been read.\n");

	//get pcap handle
	if((ihandle = pcap_open_live(options.iface, BUFSIZ, 1, poll_time, error_buffer)) == NULL) {
		fprintf(stderr, "pcap_open_live():%s \n", error_buffer);
		exit(EXIT_FAILURE);
	}

	printf("%s has been selected.\n", options.iface);

	//get netmask and ip
	pcap_lookupnet(options.iface, &ip_v4, &mask_v4, error_buffer);


	//compile the pcap filter
	if(pcap_compile(ihandle, &compiled_filter, pcap_filter, 0, mask_v4) == -1) {
		fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(ihandle));
		exit(1);
	}

	//set the filter
    if(pcap_setfilter(ihandle, &compiled_filter) == -1) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(ihandle));
        exit(1);
    }

    options.log_file = fopen(LOG_FILE_NAME, "a");

    //start sniffing
    printf("Listening %s.\n", options.iface);
    pcap_loop(ihandle, -1, catch_ssl_hsk, (u_char*)&options);


    //clean up
    printf("Cleaning up...\n");

    fclose(options.log_file);
    pcap_freecode(&compiled_filter);
    pcap_close(ihandle);

    for(i = 0; i < options.catch_num; i++) {
    	free(options.catch_table[i]);
    }
    free(options.catch_table);

	return EXIT_SUCCESS;
}

/*
 * callback function for pcap_loop
 * Catches the TCP payload content and
 * checks them against given hex pattern.
 */
void catch_ssl_hsk(u_char *args, const struct pcap_pkthdr* pkthdr,
		const u_char* packet) {

	struct ethernet_header* ethernet_h;
	struct ip_header* ip_h;
	struct tcp_header* tcp_h;
	u_char* tcp_payload;
	callback_opt* options;
	int ip_len, tcp_len, payload_len, i;
	char src_ip[20];
	char dst_ip[20];
	char content[BUFSIZ] = "";
	char hex_val[3];

	//get options
	options = (callback_opt*) args;

	//get Ethernet header
	ethernet_h = (struct ethernet_header*)(packet);
	//get IP header
	ip_h = (struct ip_header*)(packet + SIZE_ETHERNET);
	ip_len = IP_HL(ip_h) * 4;

	if(ip_len < 20) {
		fprintf(stderr, "Invalid IP header length: %d\n", ip_len);
		return;
	}

	if(ip_h->ip_p != IPPROTO_TCP) {
		fprintf(stderr, "Not a TCP header\n");
		return;
	}

	//get TCP header
	tcp_h = (struct tcp_header*)(packet + SIZE_ETHERNET + ip_len);
	tcp_len = TH_OFF(tcp_h)*4;
	if (tcp_len < 20) {
		printf("Invalid TCP header length: %d\n", tcp_len);
		return;
	}

	//get TCP payload
	tcp_payload = (u_char *)(packet + SIZE_ETHERNET + ip_len + tcp_len);
	payload_len = ntohs(ip_h->ip_len) - (ip_len + tcp_len);

	//convert payload to hex string
	for(i = 0; i < payload_len; i++) {
		sprintf(hex_val, "%.2x", tcp_payload[i]);
		strncat(content, hex_val, 3);
	}

	//search for matches
	for(i = 0; i < options->catch_num; i++) {
		if(strstr(content, options->catch_table[i]) != NULL) {
			/*printf("----------------- %d \n", i);
			print_payload(tcp_payload, payload_len);*/
			strncpy(src_ip, inet_ntoa(ip_h->ip_src), 20);
			strncpy(dst_ip, inet_ntoa(ip_h->ip_dst), 20);

			//write to log
			fprintf(options->log_file, "Caught: %s:%d to %s:%d\n",
					src_ip, ntohs(tcp_h->th_sport), dst_ip, ntohs(tcp_h->th_dport));

			fflush(options->log_file);

			if(options->rst_num > 0)
				send_rst(ethernet_h, ip_h, tcp_h, options->iface, options->rst_num);
		}
	}

}

void send_rst(struct ethernet_header* ether_h, struct ip_header* ip_h,
		struct tcp_header* tcp_h, char* iface_name, int rst_num) {

	char error_buffer[PCAP_ERRBUF_SIZE];
	libnet_t* libnet_t;
	int i;

	//get a libnet handle
	if ((libnet_t = libnet_init(LIBNET_LINK, iface_name, error_buffer)) == NULL) {
	        fprintf(stderr, "libnet_open_link_interface(): %s\n", error_buffer);
	        return;
	}


	//printf("%d - %d\n", ntohs(tcp_h->th_dport), ntohs(tcp_h->th_sport));


	//build packet from top to bottom
	if(libnet_build_tcp_options(
						(u_int8_t*)"\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000",
						20,
						libnet_t,
						0) == -1){
				fprintf(stderr, "libnet_build_tcp_options(): failed\n");
	}

	if(libnet_build_tcp(
					ntohs(tcp_h->th_dport),                //source port
					ntohs(tcp_h->th_sport),                //destination port
					ntohl(tcp_h->th_ack),                //sequence number
					0,	                   	//ack number
					TH_RST,					//flag
					1024,                   //window size
					0,						//checksum
					0,                      //urgent pointer
					LIBNET_TCP_H + 20,		//packet length
					NULL,                   //payload
					0,                      //payload length
					libnet_t,				//libnet handle
					0) == -1) {
		fprintf(stderr, "libnet_build_tcp(): failed\n");
	}


	if(libnet_build_ipv4(
				LIBNET_IPV4_H + LIBNET_TCP_H + 20,	//packet length
				0,                      //tos
				ip_h->ip_id,            //id
				0,                      //fragmentation bits
				64,                    	//TTL
				IPPROTO_TCP,            //upper layer protocol type
				0,						//checksum
				ip_h->ip_dst.s_addr,	//source address
				ip_h->ip_src.s_addr,	//destination address
				NULL,                	//payload
				0,						//payload length
				libnet_t,				//libnet handle
				0) == -1) {
		fprintf(stderr, "libnet_build_ipv4(): failed\n");
	}



	if(libnet_autobuild_ethernet(
			ether_h->ether_shost, 	//destination MAC
			ETHERTYPE_IP,			//upper layer protocol
			libnet_t				//libnet handle
			) == -1) {
		fprintf(stderr, "libnet_autobuild_ethernet(): failed\n");
	}

	for(i = 0; i < rst_num; i++) {
		if(libnet_write(libnet_t) == -1) {
			fprintf(stderr, "libnet_write(): failed\n");
		}
	}

	libnet_destroy(libnet_t);
}


//print functions from packetforward tool
void print_payload(const u_char *payload, int len) {

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}


/*
 * print data in rows of 16 bytes: offset   hex   ascii
 * 00000   4745 5420 2f20 4854   5450 2f31 2e31 0d0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x", *ch);
		ch++;
		/* print extra space after for visual aid */
		if (i%2 != 0)
			printf(" ");
		if (i == 7)
			printf("   ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf("   ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("  ");
			if (i%2 == 0)
				printf(" ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}
