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
uint16_t checksum (uint16_t *, int);
uint16_t tcp6_checksum (struct ip6_hdr, struct tcphdr);
uint16_t udp6_checksum (struct ip6_hdr, struct udphdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

