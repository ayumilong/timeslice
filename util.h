/*************************************************************************
    > File Name: common.h
    > Subject: 
    > Author: Yaolin Zhang
    > Mail: yaolinz@clemson.edu 
    > Created Time: Sun 27 Apr 2014 09:30:27 PM EDT
 ************************************************************************/
#ifndef UTIL__H
#define UTIL__H

#include <stdio.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h> 
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

struct packet {
    struct in_addr dst_ip;
    u_int dst_port;
    struct in_addr src_ip;
    u_int src_port;

    u_int len;
    u_int data_len;

    u_int seq;
    u_int ack_seq;
    u_short ip_id; //IP identification
    u_short ip_sum; //IP checksum

    int syn;
    int ack;
    int fin;
    int psh;
    int retransmit;
    int outoforder;
    int lost_previous;
    int duplicate;

    int slice_id; //Which slice this packet belongs to
	int pkt_id; //The sequence number of this packet

    struct timeval ts;

	u_char *content; //Actual data of this packet, mainly for text/html data
	u_char *content_type; //Conten type, for example, text/html or text/css 
};

struct packetNode{
	struct packetNode *next;
	struct packet *pkt;

	struct packetNode *pair; //If pkt -> content != NULL, then this packet should have a pair packet
};

struct packetListHead{
	struct packetNode* head;
	struct packetNode* tail;

	int packetCount; //Number of packets in a slice
};

struct sliceNode{
	struct sliceNode *next;

	struct timeval start_time; //The start time of this slice
	struct timeval end_time; //The end time of this slice

	size_t total_len; //Total length of data in this slice
	double bandwidth; //Bandwidth of this slice

	struct packetListHead *packetHead; //Packets that belong to this slice

	size_t http_pages; //Number of http pages in this slice
	size_t http_objects; //Number of http objects in this slice
	size_t ip_addres; //Number of different IP addresses in this slice
};

struct sliceListHead{
	struct sliceNode *head; //
	struct sliceNode *tail;

	int sliceCount; //Nubmber of slices
    int packetCount; //Number of packets in total	

	struct timeval start_time; //The start time of this sniffer
	struct timeval end_time; //The end time of this sniffer

	long long total_len; //Total length of data in this sniffer
	double bandwidth; //Bandwidth as a whole
};

//Get the offset to Network Layer data according to different Data Link Layer type 
int pcap_dloff(pcap_t *pd);
//Get each packet information and store them into pkt
void getPacket(struct packet *pkt, const struct pcap_pkthdr* pkthdr, const u_char* packet, int sid, int pid, pcap_t *desc);

void getTime(char *tmpLine, struct timeval curTime);
//Print all the result information
void printResult(struct sliceListHead *slh, int bdUnit, int pringMethod);
//Print usage information of timeslice tool
void print_usage_exit(char *name);

// Handle error with user msg
void DieWithUserMessage(const char *msg, const char *detail);
// Handle error with sys msg
void DieWithSystemMessage(const char *msg);
// Print socket address


#endif
