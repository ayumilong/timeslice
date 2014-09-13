/*************************************************************************
    > File Name: main.c
    > Subject: 
    > Author: Yaolin Zhang
    > Mail: yaolinz@clemson.edu 
    > Created Time: Sun 27 Apr 2014 04:26:39 PM EDT
 ************************************************************************/

#include <stdio.h>
#include <pcap/pcap.h>

#include "util.h"

//Global variable for packet Count Function
long  packetCount = 0; //Total packets number
pcap_t* desc; //Pacp description for process packets
int sliceInterval = 1; //Default slice interval in microseconds, 1 seconds
int bdUnit = 2; //Default bandwidth unit is MB
int printMethod = 1; //Default print method is print all the information


/**********************************************
 * void processPacket(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) 
 * - pcap filters the packets using the given filter and then calls this 
 *   function for each valid packet (we only handle tcp packets) 
 *   a packet struct is created and it is processed and placed into the
 *   slice and connection data structs
 **********************************************/
void processPacket(u_char *args, const struct pcap_pkthdr* pkthdr,const u_char* packet) {
	++packetCount; //Total packet number
	struct sliceListHead *slices = args;
	if(slices -> head == NULL){//The first packet
		slices -> start_time = pkthdr -> ts;
		slices -> head = (struct sliceNode*)malloc(sizeof(struct sliceNode));
		slices -> sliceCount = 0; 
		slices -> packetCount = 0;

		slices -> head -> next = NULL;
		slices -> head -> start_time = pkthdr -> ts;
		slices -> head -> end_time.tv_sec = pkthdr -> ts.tv_sec + sliceInterval;
	    slices -> head -> end_time.tv_usec = pkthdr -> ts.tv_usec;
		slices -> head -> total_len = 0;
		slices -> head -> bandwidth = 0;
		slices -> head -> http_pages = 0;
		slices -> head -> http_objects = 0;
		slices -> head -> ip_addres = 0;

		slices -> head -> packetHead = (struct packetListHead*)malloc(sizeof(struct packetListHead)); 
		slices -> head -> packetHead -> head = NULL;
		slices -> head -> packetHead -> tail = NULL;
		slices -> head -> packetHead -> packetCount = 0;
		slices -> tail = slices -> head;
	}
	struct packetListHead *plh = slices -> tail -> packetHead;
	if(plh -> head == NULL){//The first packet of this slice
		plh -> packetCount = 1;
		++slices -> packetCount;

		plh -> head = (struct packetNode*)malloc(sizeof(struct packetNode));
		plh -> head -> next = NULL;
		plh -> head -> pkt = (struct packet*)malloc(sizeof(struct packet));
		plh -> tail = plh -> head;

		getPacket(plh -> tail -> pkt, pkthdr, packet, slices -> sliceCount, slices -> packetCount, desc);
		if(plh -> tail -> pkt -> content != NULL){//This is a HTTP packet
			if(strcmp("text/html", plh -> tail -> pkt -> content_type) == 0){
				++slices -> tail -> http_pages;	
			}else{
					if(strcmp("get", plh -> tail -> pkt -> content_type) != 0 && strcmp("response", plh -> tail -> pkt -> content_type) != 0){
						++slices -> tail -> http_objects;
					}
			}
		}
	    slices -> tail -> total_len += plh -> head -> pkt -> len; 	
	}else{//Need to decide if the current packet is in the current slice or in a new slice
		if(pkthdr -> ts.tv_sec < slices -> tail -> end_time.tv_sec){//Should be in the current slice
			plh -> tail -> next = (struct packetNode*)malloc(sizeof(struct packetNode));
			plh -> tail = plh -> tail -> next; //The current packet is the new tail
			plh -> tail -> next = NULL;
			plh -> tail -> pkt = (struct packet*)malloc(sizeof(struct packet));
			++slices -> packetCount;
			++plh -> packetCount;
			
			getPacket(plh -> tail -> pkt, pkthdr, packet, slices -> sliceCount, slices -> packetCount, desc);
			if(plh -> tail -> pkt -> content != NULL){//This is a HTTP packet
				if(strcmp("text/html", plh -> tail -> pkt -> content_type) == 0){
					++slices -> tail -> http_pages;	
				}else{
					if(strcmp("get", plh -> tail -> pkt -> content_type) != 0 && strcmp("response", plh -> tail -> pkt -> content_type) != 0){
						++slices -> tail -> http_objects;
					}
				}
			}
	    	slices -> tail -> total_len += plh -> tail -> pkt -> len; 	
		}else{//A new slice will be created and the curret packet is the first packet in this slice
			slices -> total_len += slices -> tail -> total_len;
			slices -> tail -> bandwidth = slices -> tail -> total_len / (double)sliceInterval;
			slices -> tail -> next = (struct sliceNode*)malloc(sizeof(struct sliceNode));	
			slices -> tail = slices -> tail -> next;
			slices -> tail -> next = NULL;
			slices -> tail -> start_time = pkthdr -> ts;
			slices -> tail -> end_time.tv_sec =  pkthdr -> ts.tv_sec + sliceInterval;
			slices -> tail -> end_time.tv_usec =  pkthdr -> ts.tv_usec + sliceInterval;
			slices -> tail -> total_len = 0;
			slices -> tail -> bandwidth = 0;
			slices -> tail -> http_pages = 0;
			slices -> tail -> http_objects = 0;
			slices -> tail -> ip_addres = 0;

			slices -> tail -> packetHead = (struct packetListHead*)malloc(sizeof(struct packetListHead)); 
			slices -> tail -> packetHead -> head = NULL;
			slices -> tail -> packetHead -> tail = NULL;
			slices -> tail -> packetHead -> packetCount = 1;
			++slices -> sliceCount;

			struct packetListHead *plh = slices -> tail -> packetHead;
			plh -> packetCount = 1;
			++slices -> packetCount;

			plh -> head = (struct packetNode*)malloc(sizeof(struct packetNode));
			plh -> head -> next = NULL;
			plh -> head -> pkt = (struct packet*)malloc(sizeof(struct packet));
			plh -> tail = plh -> head;

			getPacket(plh -> tail -> pkt, pkthdr, packet, slices -> sliceCount, slices -> packetCount, desc);
			if(plh -> tail -> pkt -> content != NULL){//This is a HTTP packet
				if(strcmp("text/html", plh -> tail -> pkt -> content_type) == 0){
					++slices -> tail -> http_pages;	
				}else{
					if(strcmp("get", plh -> tail -> pkt -> content_type) != 0 && strcmp("response", plh -> tail -> pkt -> content_type) != 0){
						++slices -> tail -> http_objects;
					}
				}
			}
	    	slices -> tail -> total_len += plh -> tail -> pkt -> len; 	
		}
	}
}

void getCount(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
	packetCount++;
}

int main(int argc, char **argv){
	char *filter_str = "tcp";
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_bpf;
	int allCount = 0;
	int count = -1;
    char *fname = NULL;

	struct sliceListHead slices;
	slices.head = NULL;
	slices.tail = NULL;
	slices.sliceCount = 0;
	slices.packetCount = 0;
	slices.total_len = 0;
	slices.bandwidth = 0;


	int c;

	while ((c = getopt(argc, argv, "p:b:f:t:c:h:C")) != -1){
	    switch (c) {
			case 'p':
				if(strcmp(optarg, "a") == 0){
					printMethod = 1; //Print all the information
				}else if(strcmp(optarg, "p") == 0){
					printMethod = 2; //Print pages number for each  slice plus summary info
				}else if(strcmp(optarg, "o") == 0){
					printMethod = 3; //Print objects number for each slice plus summary info
				}else if(strcmp(optarg, "b") == 0){
					printMethod = 4; //Print bandwidth for each slice plus summary info
				}else if(strcmp(optarg, "d") == 0){//Print packets number for each slice plus summary info
					printMethod = 5;
				}else if(strcmp(optarg, "s") == 0){//Just print summary info
					printMethod = 6;
				}else{
	            	print_usage_exit(argv[0]);
				}
				break;
			case 'b':
				if(strcmp(optarg, "m") == 0){
					bdUnit = 1;
				}else if(strcmp(optarg, "k") == 0){
					bdUnit = 2;
				}else if(strcmp(optarg, "b") == 0){
					bdUnit = 3;
				}else{
	            	print_usage_exit(argv[0]);
				}
				break;
	        case 'f': //Filter
	            filter_str = (char *)malloc(strlen(optarg) + 8);
	            strcat(filter_str,"tcp && (");
	            strcat(filter_str,optarg);
	            strcat(filter_str,")");
	            printf("The f params:  %s\n",filter_str);
	            break;
	        case 't': //Slice interval, in microseconds
				sliceInterval = atoi(optarg);
	            break;
	        case 'c': //Process count number of packets
	            count = atoi(optarg);
	            break;
	        case 'h': //Show useage information
	            print_usage_exit(argv[0]);
	            break;
	        case 'C':  /* user has indicated that they want to get a count of all the packets in the trace file*/
				allCount = 1;
	            break;
	        default:
	            break;
	    }
	}	

	/* must have a file to read in */
    if(optind < argc) {
        fname = argv[optind];
    } else {
        printf("No File Specified\n");
        print_usage_exit(argv[0]);
    }

	/* open the packet dump file */
    desc = pcap_open_offline(fname, errbuf);

    if(desc == NULL) {
        printf("%s\n",errbuf); 
        print_usage_exit(argv[0]);
    }

	/* If the user wanted a count of all the packets (switch -C), count the packets -- send the message to stdin, and get out.*/
    if(allCount == 1){
        pcap_loop(desc,count, getCount, (u_char*)NULL);
	    printf("%ld packets in trace file.\n", packetCount);
	    exit(0);
    }

	char *endp = strrchr(filter_str, ')');
	if (endp != NULL){
	   *(++endp) = '\0';
	}

	//Compile the filter
	if(pcap_compile(desc,&filter_bpf, filter_str,0,0) == -1) {
        fprintf(stderr,"Error with filter: %s\n", filter_str); 
        print_usage_exit(argv[0]);
    }

    /* Pass the bpf filter back to pcap */
    if(pcap_setfilter(desc,&filter_bpf) == -1) {
        fprintf(stderr,"pcap_setfilter error\n");
        print_usage_exit(argv[0]);
    }

	/* Read filtered packets and send the to callback 
     * count is negative, so read until error (EOF) */
    pcap_loop(desc, count, processPacket, (u_char*)&slices);

	//Process last slice's end time and the end time of the whole process
	slices.tail -> end_time = slices.tail -> packetHead -> tail -> pkt -> ts;
	slices.end_time = slices.tail -> packetHead -> tail -> pkt -> ts;
	slices.bandwidth = slices.total_len / ((double)slices.sliceCount * sliceInterval);

	printResult(&slices, bdUnit, printMethod);

	return 0;
}
