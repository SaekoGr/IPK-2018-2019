/**
 * http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
 * Súbor: tcp6_ll.c 
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_TCP, INET6_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>      // struct ip6_hdr
#define __FAVOR_BSD           // Use BSD format of tcp header
#include <netinet/tcp.h>      // struct tcphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()
#include <iostream>

#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <regex>
#include <pcap.h>
#include <csignal>

/**
 * http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
 * Súbor: tcp6_ll.c 
 */
#define TCP_HDRLEN 20  // TCP header length, excludes options data
#define ETH_HDRLEN 14  // Ethernet header length
#define IP6_HDRLEN 40  // IPv6 header length
#define UDP_HDRLEN  8  // UDP header length, excludes data

#define NO_PARAMETERS 0
#define TOO_MANY_PARAMETERS 6
#define OK 0
#define ARG_INVALID 1
#define INTERNAL_ERROR 2
#define MAXLINE 1024
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define PCKT_LEN 8192
#define IPV6PCKT_LEN 2000

pcap_t *handle;
int current_port;
bool ipv4_flag = false;
bool ipv6_flag = false;

/**
 * https://stackoverflow.com/questions/51662138/tcp-syn-flood-using-raw-socket-in-ubuntu?fbclid=IwAR0lXO0WlhnHh2dx71zecLolnA-57aUgcPDsDCVkLJnL2l9eZHteotcZw6c
 */
struct pseudo_header_tcp   
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
     
    struct tcphdr tcp;
};


struct pseudo_header_udp   
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
     
    struct udphdr udp;
};

struct ipv6_header
{
    unsigned int
        version : 4,
        traffic_class : 8,
        flow_label : 20;
    uint16_t length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct in6_addr src;
    struct in6_addr dst;
};


/**
 * @brief structure Ports for input arguments
 */
struct Ports{
    std::string ports;
    bool has_range;
    bool multiple_values;
    int from = 0;
    int to = 0;
    std::string domain_name;
    std::string dest_ip;
    std::string source_ip;
    std::string interface;
};

/**
 * 
 */
typedef struct tElem{
    struct tElem *next;
    int value;
} *tElemPtr;

/**
 * 
 */
typedef struct{
    tElemPtr First;
    tElemPtr Last;
} tList;

// Function prototypes

/**
 * @brief disposes of list L
 * 
 * @param L - list containing dynamically allocated numbers of ports
 * 
 * @source https://github.com/SaekoGr/IAL-2018-2019/blob/master/ial_2018_du1/c201/c201.c
 * @author Sabína Gregušová (xgregu02) for IAL
 */
void DisposeList(tList *L)

/**
 * @brief initializes list L
 * 
 * @param L - list to be dynamically allocated
 * @param value_list - list of ports to be scanned
 * 
 * @source https://github.com/SaekoGr/IAL-2018-2019/blob/master/ial_2018_du1/c201/c201.c
 * @author Sabína Gregušová (xgregu02) for IAL
 */
void InitList(tList *L, std::string value_list);


/**
 * @brief prepares the header for final output
 * 
 * @param domain_name - name of the domain
 * @param ip_address - ip address of the domain
 */
void write_domain_header(std::string domain_name, std::string ip_address);


/**
 * @brief official check sum for headers (IPv4)
 * 
 * @param ptr
 * @param nbytes
 * @return unsigned short
 * 
 * @source https://stackoverflow.com/questions/51662138/tcp-syn-flood-using-raw-socket-in-ubuntu?fbclid=IwAR0lXO0WlhnHh2dx71zecLolnA-57aUgcPDsDCVkLJnL2l9eZHteotcZw6c
 * @author: zx485
 */
unsigned short csum(unsigned short *ptr,int nbytes);

/**
 * @brief function for handling TCP for IPv6
 * 
 * @param order_num number of port to be scanned
 * @param real_ports structure for TCP containing all the necessary information
 * 
 * Sending TCP with IPv6
 * @source http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
 * @author P. David Buchan
 * @email pdbuchan@yahoo.com
 * @released March 6, 2015
 * @file tcp6_ll.c
 * 
 * Catching the response pakets
 * @source https://www.devdungeon.com/content/using-libpcap-c
 * @author couldn't resolve
 * 
 */
void TCP_IPv6(int order_num, struct Ports real_ports);

/**
 * @brief function for handling TCP for IPv4
 * 
 * @param order_num number of port to be scanned
 * @param real_ports structure for TCP containing all the necessary information
 * 
 * Sending TCP with IPv4
 * @source https://www.tenouk.com/Module43b.html
 * @author couldn't resolve
 * 
 * Catching the response pakets
 * @source https://www.devdungeon.com/content/using-libpcap-c
 * @author couldn't resolve
 * 
 */
void TCP_IPv4(int order_num, struct Ports real_ports);


/**
 * @brief function for handling UDP for IPv6
 * 
 * @param order_num number of port to be scanned
 * @param real_ports structure for UDP containing all the necessary information
 * 
 * Sending UDP with IPv6
 * @source http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
 * @author P. David Buchan
 * @email pdbuchan@yahoo.com
 * @released March 6, 2015
 * @file udp6_ll.c
 * 
 * Catching the response pakets
 * @source https://www.devdungeon.com/content/using-libpcap-c
 * @author couldn't resolve
 * 
 */
void UDP_IPv6(int order_num, struct Ports real_ports);

/**
 * @brief function for handling TCP for IPv4
 * 
 * @param order_num number of port to be scanned
 * @param real_ports structure for TCP containing all the necessary information
 * 
 * Sending TCP with IPv4
 * @source https://www.tenouk.com/Module43a.html
 * @author couldn't resolve
 * 
 * Catching the response pakets
 * @source https://www.devdungeon.com/content/using-libpcap-c
 * @author couldn't resolve
 * 
 */
void UDP_IPv4(int order_num, struct Ports real_ports);

/**
 * @brief goes through the port range and sends it to process 
 * 
 * @param TCP_ports structure that contains necessary information for TCP protocol
 */
void process_TCP(struct Ports TCP_ports);

/**
 * @brief goes through the port range and sends it to process 
 * 
 * @param UDP_ports structure that contains necessary information for UDP protocol
 */
void process_UDP(struct Ports UDP_ports);

/**
 * @brief help function for checksum (IPv6)
 * 
 * @param addr given address
 * @param len given length
 * 
 * @return pointer to uint16_t
 * 
 * @source http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
 * @author P. David Buchan
 * @email pdbuchan@yahoo.com
 * @released March 6, 2015
 * @file udp6_ll.c
 */
uint16_t checksum (uint16_t *addr, int len);

/**
 * @brief allocates memory for an array of chars
 * 
 * @param len given length
 * 
 * @return pointer to char
 * 
 * @source http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
 * @author P. David Buchan
 * @email pdbuchan@yahoo.com
 * @released March 6, 2015
 * @file tcp6_ll.c
 */
char *allocate_strmem (int len);

/**
 * @brief allocates memory for an array of unsigned chars
 * 
 * @param len given length
 * 
 * @return pointer to uint8_t
 * 
 * @source http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
 * @author P. David Buchan
 * @email pdbuchan@yahoo.com
 * @released March 6, 2015
 * @file tcp6_ll.c
 */
uint8_t *allocate_ustrmem (int len);

/**
 * @brief allocates memory for an array of ints
 * 
 * @param len given length
 * 
 * @return pointer to integer
 * 
 * @source http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
 * @author P. David Buchan
 * @email pdbuchan@yahoo.com
 * @released March 6, 2015
 * @file tcp6_ll.c
 */

int *allocate_intmem (int len);

/**
 * @brief builds IPv6 TCP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
 * 
 * @param iphdr IP header
 * @param tcphdr TCP header
 * 
 * @return calculated checksum
 * 
 * @source http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
 * @author P. David Buchan
 * @email pdbuchan@yahoo.com
 * @released March 6, 2015
 * @file tcp6_ll.c
 */
uint16_t tcp6_checksum (struct ip6_hdr iphdr, struct tcphdr tcphdr);

/**
 * @brief builds IPv6 UDP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
 * 
 * @param iphdr IP header
 * @param tcphdr UDP header
 * @param payload data
 * @param payloadlen length of data
 * 
 * @return calculated checksum
 * 
 * @source http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
 * @author P. David Buchan
 * @email pdbuchan@yahoo.com
 * @released March 6, 2015
 * @file tcp6_ll.c
 */
uint16_t udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen);
