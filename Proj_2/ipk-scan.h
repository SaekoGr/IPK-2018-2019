#define NO_PARAMETERS 0
#define TOO_MANY_PARAMETERS 6
#define OK 0
#define ARG_INVALID 1
#define INTERNAL_ERROR 2
#define MAXLINE 1024

pcap_t *handle;

/* Structure of the IP header */
// both structure are from https://www.tenouk.com/Module43b.html
    struct ipheader {
        unsigned char      iph_ihl:5, /* Little-endian */
                            iph_ver:4;
        unsigned char      iph_tos;
        unsigned short int iph_len;
        unsigned short int iph_ident;
        unsigned char      iph_flags;
        unsigned short int iph_offset;
        unsigned char      iph_ttl;
        unsigned char      iph_protocol;
        unsigned short int iph_chksum;
        unsigned int       iph_sourceip;
        unsigned int       iph_destip;
    };

/* Structure of the TCP header */
// both structures are from: https://www.tenouk.com/Module43b.html
struct tcpheader {
    unsigned short int   tcph_srcport;
    unsigned short int   tcph_destport;
    unsigned int             tcph_seqnum;
    unsigned int             tcph_acknum;
    unsigned char          tcph_reserved:4, tcph_offset:4;
    unsigned int
       tcp_res1:4,      /*little-endian*/
       tcph_hlen:4,     /*length of tcp header in 32-bit words*/
       tcph_fin:1,      /*Finish flag "fin"*/
       tcph_syn:1,       /*Synchronize sequence numbers to start a connection*/
       tcph_rst:1,      /*Reset flag */
       tcph_psh:1,      /*Push, sends data to the application*/
       tcph_ack:1,      /*acknowledge*/
       tcph_urg:1,      /*urgent pointer*/
       tcph_res2:2;
    unsigned short int   tcph_win;
    unsigned short int   tcph_chksum;
    unsigned short int   tcph_urgptr;
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

/**
 * 
 */
struct pseudo_header{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
};