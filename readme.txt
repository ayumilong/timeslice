	We wrote all the codes by ourselves. We also wrote a Makefile to help compile the whole project so you can just type make to compile our project and after that you will get a executable file called run then you can type “./run –h” to show the details about how to run our project. 
I have tested my program with the trace files in the website http://people.cs.clemson.edu/~jmarty/traces/ including 20140421 _130127440.pcap and 20140421_130127480.pcap. All the results that show in this paper are got from 20140421_130127440.pcap. You can run our project with any trace file as you want.

	An example to run our project:
	./run -t 2 -p a -b k	trace_file_name_here      Run the timeslie with 2 seconds(-t) slice interval, print all the statistic information(-p a), print data size and bandwidth in KB(-b k)

The current version of the timeslice tool has the following code files
Filename 	Purpose 
util.h 		Contains all the data structures definition and functions definition 
util.c 		Contains implementation of functions which are defined in util.h 
main.c 		Contains the main program, does the option parsing and call the pcap library with appropriate parameters and a designated handler 

Data structures:
The basic data structures used in this tool are tabulated below:
Name					Description
Struct packet			This is the simplest structure which stores packet level information for each packet returned by the pcap library. Storing that information allows us to abstract out the differences in packet formats to a single function, which actually reads the data into the packet structure.
Struct packetNode		This structure holds data for a packet in a packets list
Struct packetListHead	This structure holds data that represents a list of packets that belong to a same slice
Struct sliceNode		This structure holds all the information about a slice in a slice list
Struct sliceListHead	This structure holds data that represents a list of slice given a trace file as an input

Control flow
•	The main.c file is the driver as it has the main program contained in it. Firstly, it parses all the parameters and do some necessary initialization. Next, it passes a function pointer to the function processPacket to the pcap library which is called each time a complete frame is extracted from the trace file.
•	The function processPacket will maintain some data structure that used to store all the packets information is a slice list. It will call getPacket to extract each packet information and store it in a packet structure with in a packet list which belong to the current slice. 
•	The main function then calls the print_results function to process and print slice specific stats.

Functions
We shall list the important functions present in the source code present in the main.c and the util.c code files.
main.c
void  processPacket(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)	
Pcap filters the packets using the given filter and then calls this function for each valid packet (we only handle TCP packets) a packet struct is created and it is processed and placed into the slice and connection data structs

void getCount(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)	
This function is registered as the callback handler if we only want to count the number of packets in the trace (turned on by the –C option).


util.c
void print_results(struct sliceListHead *slh, int bdUnit, int pringMethod)	
Outputs the information for each slice 

void print_usage_exit(char *name)	
Prints the appropriate usage of the tool if invoked incorrectly from the command line.

int pcap_dloff(pcap_t *pd)	
Get the offset to Network Layer data according to different Data Link Layer type

Void getTime(char *tmpLine, struct timeval curTime)	
Get printable time given a struct timeval as an argument

void getPacket(struct packet *pkt, const struct pcap_pkthdr* pkthdr, const u_char* packet, int sid, int pid, pcap_t *desc)
Get each packet information and store them into pkt

