/*************************************************************************
    > File Name: common.c
    > Subject: 
    > Author: Yaolin Zhang
    > Mail: yaolinz@clemson.edu 
    > Created Time: Mon 28 Apr 2014 10:08:37 AM EDT
 ************************************************************************/



#include "util.h"

//Get the offset to Network Layer data according to different Data Link Layer time
int pcap_dloff(pcap_t *pd){
	int offset = -1;
	switch (pcap_datalink(pd)) {
		case DLT_EN10MB:
			offset = 14;
			break;
		case DLT_IEEE802:
			offset = 22;
			break;
		case DLT_FDDI:
			offset = 21;
			break;
		default:
			printf("unsupported datalink type!");
			exit(1);
			break;
	}
	return (offset);
}

int httpCount = 0;

char *getType(const char *src){
	char *start = strchr(src, ' ') + 1;
	char t[255];
	int i = 0;
	while(*start == '/' || isalpha(*start)){
		t[i++] = *start;
		++start;
	}
	t[i] = '\0';
	char *type = (u_char *)malloc((i + 1) * sizeof(char));
	memcpy(type, t, i);
	type[i] = '\0';
	return type;
}

int getState(int pid, const char *src){
	char *http = strstr(src, "HTTP");
	if(http == NULL){
		return -1;
	}
	char *start = strchr(src, ' ') + 1;
	if(start == NULL){
		return -1;
	}
	char r[255];
	int i = 0;
	while(isdigit(*start)){
		r[i++] = *start;
		++start;
	}
	r[i] = '\0';
	return atoi(r);
}

void getPacket(struct packet *pkt, const struct pcap_pkthdr* pkthdr, const u_char* packet, int sid, int pid, pcap_t *desc){
	struct ip *ip_h = (struct ip *)(packet + pcap_dloff(desc));
    struct tcphdr *tcp_h  = (struct tcphdr*) (packet + sizeof(struct ether_header) + sizeof(struct ip));
	//This pointer shall point to the first byte of the application data

	/* extract packet data */
	pkt -> slice_id = sid;
	pkt -> pkt_id = pid;

    pkt -> ts = pkthdr -> ts;
    pkt -> len = ntohs(ip_h -> ip_len); //Total length of IP packet 
    pkt -> data_len = ntohs(ip_h -> ip_len) - (ip_h -> ip_hl)*4 - (tcp_h -> doff)*4; //Length of data in a TCP segment
    pkt -> dst_ip = ip_h -> ip_dst;
    pkt -> dst_port = ntohs(tcp_h -> dest);
    pkt -> src_ip = ip_h -> ip_src;
    pkt -> src_port = ntohs(tcp_h -> source);


    /* check for SYN or FIN flag */
    pkt -> fin = (tcp_h -> fin) ? 1 : 0; 
    pkt -> syn = (tcp_h -> syn) ? 1 : 0;
    pkt -> psh = (tcp_h -> psh) ? 1 : 0;
    pkt -> ack = (tcp_h -> ack) ? 1 : 0;

    pkt -> seq = ntohl(tcp_h -> seq);
    pkt -> ack_seq = ntohl(tcp_h -> ack_seq);
    pkt -> ip_id = ip_h -> ip_id;
    pkt -> ip_sum = ip_h -> ip_sum;

    pkt -> retransmit = 0;
    pkt -> outoforder = 0;
    pkt -> duplicate = 0;
    pkt -> lost_previous = 0;

	const u_char *app_data_ptr = packet + sizeof(struct ether_header) + sizeof(struct ip) + tcp_h->doff * 4;//Tcp_h->doff points to the hlen field in the TCP header
	
	if(pkt -> ack == 1 && (pkt -> psh == 1 || pkt -> fin == 1)){ //TCP connection is established
		if(pkt -> dst_port == 80){//HTTP GET
			++httpCount;
			pkt -> content = (u_char *)malloc(pkt -> data_len + 1);
			memcpy(pkt -> content, app_data_ptr, pkt -> data_len);
			pkt -> content[pkt -> data_len] = '\0';

			pkt -> content_type = (u_char *)malloc(4 * sizeof(char));
			memcpy(pkt -> content_type, "get", 3 * sizeof(char));
			pkt -> content_type[3] = '\0';
		}else if(pkt -> src_port == 80){//HTTP RESPONSE
			++httpCount;
			pkt -> content = (u_char *)malloc(pkt -> data_len + 1);
			memcpy(pkt -> content, app_data_ptr, pkt -> data_len);
			pkt -> content[pkt -> data_len] = '\0';

			int state = getState(pid, pkt -> content);
			if(state == 200){ //HTTP OK
				char *type = strstr(pkt -> content, "Content-Type");
		    	if(type != NULL){
					pkt -> content_type = getType(type);
				}else{
					pkt -> content_type = "response";
				}	
			}else{
				pkt -> content_type = "response"; //Gerneral type
			}	
		}else{
			pkt -> content = NULL;
			pkt -> content_type = NULL;
		}
	}else{
		pkt -> content = NULL;
		pkt -> content_type = NULL;
	}
}

const unsigned int TIME_LEN = 50; //The length of timestamp

void getTime(char *tmpLine, struct timeval curTime){
	sprintf(tmpLine, "%s ",  (char *)ctime((const time_t *)&(curTime.tv_sec)));

	//remove the CR that ctime adds
	tmpLine[strlen(tmpLine) - 2] = 0x0;
	tmpLine[strlen(tmpLine) - 1] = 0x0;
	tmpLine[strlen(tmpLine) - 4] = 0x0;
}	

void printResult(struct sliceListHead *slh, int bdUnit, int printMethod){
	char *wday[]={"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
	char startTime[TIME_LEN]; 
	char endTime[TIME_LEN]; 
	struct sliceNode *sh = slh -> head;
	int id = 1;
	while(sh != slh -> tail){
		getTime(startTime, sh -> start_time);
		getTime(endTime, sh -> end_time);
		if(printMethod == 1){//Print all information
			if(bdUnit == 1){ //Bandwidth in MB
				printf("%d    %d    %s    %.2fMB    %.2fMB/s    %d	%d\n", id, sh -> packetHead -> packetCount, startTime, sh -> total_len / (1024 * 1024.0), sh -> bandwidth / (1024 * 1024), sh -> http_pages, sh -> http_objects);
			}else if(bdUnit == 2){//Bandwidth in KB
				printf("%d    %d    %s    %.2fKB    %.2fKB/s    %d	%d\n", id, sh -> packetHead -> packetCount, startTime, sh -> total_len / (1024.0), sh -> bandwidth / (1024), sh -> http_pages, sh -> http_objects);
			}else if(bdUnit == 3){//Bandwidth in Byte
				printf("%d    %d    %s    %dB    %.2fB/s    %d	%d\n", id, sh -> packetHead -> packetCount, startTime, sh -> total_len, sh -> bandwidth, sh -> http_pages, sh -> http_objects);
			}
		}else if(printMethod == 2){//Print pages for each slice
			printf("%d    %d\n", id, sh -> http_pages);
		}else if(printMethod == 3){//Print objects for each slice
			printf("%d    %d\n", id, sh -> http_objects);
		}else if(printMethod == 4){//Print bandwidth for each slice
			if(bdUnit == 1){ //Bandwidth in MB
				printf("%d	%.2f\n", id, sh -> bandwidth / (1024 * 1024));
			}else if(bdUnit == 2){//Bandwidth in KB
				printf("%d	%.2f\n", id, sh -> bandwidth / (1024));
			}else if(bdUnit == 3){//Bandwidth in Byte
				printf("%d	%.2f\n", id, sh -> bandwidth);
			}
		}else if(printMethod == 5){//Print packets number for each slice
			printf("%d    %d\n", id, sh -> packetHead -> packetCount);
		}else if(printMethod == 6){//Print nothing here
		}
		++id;
		sh = sh -> next;
	}
	printf("----------------------------------------------------------------\n");
	printf("Total packets: %d    ", slh -> packetCount);
	printf("Total slices: %d    \n", slh -> sliceCount);
	printf("----------------------------------------------------------------\n");
	getTime(startTime, slh -> start_time);
	getTime(endTime, slh -> end_time);
	printf("Start time: %s    ", startTime);
	printf("End time: %s\n", endTime);
	printf("----------------------------------------------------------------\n");
	if(bdUnit == 1){
		printf("Total data size: %.2f    ", slh -> total_len / (1024 * 1024.0));
		printf("Average bandwidth: %.2f\n", slh -> bandwidth / (1024 * 1024.0));
	}else if(bdUnit == 2){
		printf("Total data size: %.2f    ", slh -> total_len / (1024.0));
		printf("Average bandwidth: %.2f\n", slh -> bandwidth / (1024.0));
	}else if(bdUnit == 3){
		printf("Total data size: %d    ", slh -> total_len);
		printf("Average bandwidth: %.2f\n", slh -> bandwidth);
	}
	printf("----------------------------------------------------------------\n");
}

 

void print_usage_exit(char *name){
     printf("USAGE: \n"
            "%s [OPTION]... file\n"
            "   where file is a packet capture (only tcp packets are processed).\n"
            "   Results are printed to stdout in the form:\n" 
            "   [slice number] [slice packets number] [slice start time] [slice data size] [slice bandwidth] [slice web pages number] [slice web objects number]\n"
	    "   If you want to use default values for parameters then you do not need to input any options\n"
            "Options:\n"
			" -p c			 what information do you want, 'a' means all info, 'p' means web pages info, 'o' means web objects info, 'b' means bandwidth info, 'd' means packets number info, 's' means summary info(default 'a')\n"
            " -t n           slice interval seconds (default 1.0)\n"
            " -b c           unit for bandwidth and data size, 'm' for MB, 'k' for KB, 'b' for B(default 'k')\n"
			" -f s			 filter for filting packets\n"
            " -c n           only process n packets: cannot use with -E n\n"
			" -h			 printf usage infomation\n"

	    	" -C             get count of all packets in trace file\n"
            "\n", name, name);
     exit(1);
}
