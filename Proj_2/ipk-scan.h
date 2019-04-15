#define NO_PARAMETERS 0
#define TOO_MANY_PARAMETERS 6
#define OK 0
#define ARG_INVALID 1
#define INTERNAL_ERROR 2
#define MAXLINE 1024

/**
 * structure Ports for input arguments
 */
struct Ports{
    std::string ports;
    bool has_range;
    bool multiple_values;
    int from = 0;
    int to = 0;
    std::string domain_name;
    std::string ip_address;
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