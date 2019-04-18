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

