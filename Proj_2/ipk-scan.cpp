#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "ipk-scan.h"


/**
 * @brief class for parsing the input arguments
 */
class InputArgument{
    public:
        bool pt_tcp_flag = false;
        bool pu_udp_flag = false;
        bool interface_flag = false;
        bool ipv4_flag = false;
        bool ipv6_flag = false; 
        std::string domain_name;
        std::string ip_address;
        std::string interface;
        Ports TCP_ports;
        Ports UDP_ports;
        
        /**
         * @brief parses the input arguments
         * 
         * @param argc - number of args
         * @param argv - array of args
         */
        void parse(int argc, char *argv[]){
            int counter = 1;

            // too many or too few arguments
            if(argc == 1 || argc > 8){
                std::cerr <<"Invalid input arguments"<< std::endl;
                exit(ARG_INVALID);
            }

            // must be uneven number of arguments
            if(argc % 3 != 0){
                std::cerr <<"Invalid input arguments"<< std::endl;
                exit(ARG_INVALID);
            }

            // iterate through all arguments
            while(counter < argc){
                    // TCP flags
                if(strcmp(argv[counter],"-pt") == 0){
                    this->pt_tcp_flag = true;
                    counter++;
                    if(counter < argc){
                        this->check_range(&TCP_ports, argv[counter]);
                        if(TCP_ports.has_range){
                            TCP_ports.from = this->border_from(TCP_ports.ports);
                            TCP_ports.to = this->border_to(TCP_ports.ports);
                        }
                    }
                    else{   // ERROR
                        std::cerr <<"Invalid input arguments"<< std::endl;
                        exit(ARG_INVALID);
                    }
                }   // UDP flags
                else if(strcmp(argv[counter],"-pu") == 0){
                    this->pu_udp_flag = true;
                    counter++;
                    if(counter < argc){
                        this->check_range(&UDP_ports, argv[counter]);
                        if(UDP_ports.has_range){
                            UDP_ports.from = this->border_from(UDP_ports.ports);
                            UDP_ports.to = this->border_to(UDP_ports.ports);
                        }
                    }
                    else{   // ERROR
                        std::cerr <<"Invalid input arguments"<< std::endl;
                        exit(ARG_INVALID);
                    }
                }   // INTERFACE
                else if(strcmp(argv[counter], "-i") == 0){
                    this->interface_flag = true;
                    counter++;
                    if(counter < argc){
                        this->interface.assign(argv[counter]);
                    }
                }
                // DOMAIN NAME | IP ADDRESS
                else if(strcmp(argv[counter],argv[(argc-1)]) == 0){
                    this->resolve_ip_or_host(argv[counter]);
                }
                
                else{       // ERROR
                    std::cerr <<"Invalid input arguments"<< std::endl;
                    exit(ARG_INVALID);
                }
                counter++;
            }

            // check for existence of interface
            if(this->interface_flag){

            }
            else{   // assign default
                this->get_interface();
            }

            //this->debug();
        }

    private:

        /**
         * http://man7.org/linux/man-pages/man3/getifaddrs.3.html
         */
        void get_interface(){
            struct ifaddrs* ifaddr, *ifa;
            int family, s, n;
            char host[NI_MAXHOST];
            bool found = false;

            // get info about interface
            if(getifaddrs(&ifaddr) == -1){
                fprintf(stderr, "Error getting interface\n");
                exit(INTERNAL_ERROR);
            }

            for(ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++){
                if(ifa->ifa_addr == NULL)
                    continue;

                family = ifa->ifa_addr->sa_family;

                // TODO IPV4/IPV6
                if(family == AF_INET || family == AF_INET6){
                    s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : 
                                                                         sizeof(struct sockaddr_in6),
                                                    host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                    if(s != 0){
                        fprintf(stderr, "getnameinfo failed\n");
                        exit(INTERNAL_ERROR);
                    }

                    
                    printf("address: <%s>\n", host);
                    if(!this->interface_flag){
                        if(ifa->ifa_flags & IFF_LOOPBACK){
                            found = true;
                            this->interface.assign(host);
                            break;
                        }
                    }
                    else{
                        if(strcmp(this->interface.c_str(), ifa->ifa_name) == 0){
                            found = true;
                            break;
                        }
                    }

                }
                printf("Name of interface is %s\n", ifa->ifa_name);
            }

            freeifaddrs(ifaddr);

            if(!found){
                fprintf(stderr, "Interface error\n");
                exit(INTERNAL_ERROR);
            }
        }

        /**
         * @brief gets the border value of port_list
         * 
         * @param port_list - list of all the ports
         * @return integer number that indiciates from range
         */
        int border_from(std::string port_list){
            std::string from;

            // get from value
            for(unsigned int i = 0; i < (sizeof port_list - 1); i++){
                if(port_list[i] == '-'){
                    break;
                }
                from = from + port_list[i];
            }
            return std::stoi(from);

            // cannot be empty
            if(from.empty()){
                fprintf(stderr, "From range cannot be empty\n");
                exit(INTERNAL_ERROR);
            }
            // cannot be negative
            if(std::stoi(from) < 0){
                fprintf(stderr, "Port cannot be negative\n");
                exit(INTERNAL_ERROR);
            }

            return std::stoi(from);
        }

        /**
         * @brief gets the border value of port_list
         * 
         * @param port_list - list of all the ports
         * @return integer number that indiciates to range
         */
        int border_to(std::string port_list){
            std::string to;

            // get to value
            bool now = false;
            for(unsigned int i = 0; i < (sizeof port_list - 1); i++){
                if(port_list[i] == '\0'){
                    break;
                }
                if(now){
                    to = to + port_list[i];
                }

                if(port_list[i] == '-'){
                    now = true;
                }    
            }

            // cannot be empty
            if(to.empty()){
                fprintf(stderr, "From range cannot be empty\n");
                exit(INTERNAL_ERROR);
            }
            // cannot be negative
            if(std::stoi(to) < 0){
                fprintf(stderr, "Port cannot be negative\n");
                exit(INTERNAL_ERROR);
            }

            return std::stoi(to);

        }

        /**
         * @brief sets flags of Ports structure for range and multiple values
         * 
         * @param port_list - list of ports
         */
        void check_range(struct Ports* current_ports, char* port_list){
            current_ports->ports.assign(port_list);

            // check for range 
            char* range_exist = strchr(port_list, '-');
            if(range_exist != NULL){
                current_ports->has_range = true;
                current_ports->multiple_values = true;
                return;
            }
            else{
                current_ports->has_range = false;
            }
            // check for multiple values
            char* multiple_values = strchr(port_list, ',');
            if(multiple_values != NULL){
                current_ports->multiple_values = true;
            }
            else{
                current_ports->multiple_values = false;
            }
        }

        /**
         * 
         */
        bool is_ip(char* value){
            for(unsigned int i = 0; i < strlen(value); i++){
                if(value[i] != '.' and !isdigit(value[i])){
                    return false;
                }
            }
            return true;
        }

        /**
         * @brief 
         */
        void resolve_ip_or_host(char* value){
            if(is_ip(value)){   // value is ip_address
                this->ip_address.assign(value);
                this->ip_to_hostname();
            }
            else{               // value is domain name
                this->domain_name.assign(value);
                this->hostname_to_ip();
            }
        }

        /**
         * @brief convert ip address to domain name
         */
        void ip_to_hostname(){
            struct hostent *he;
            struct in_addr ipv4addr;
            inet_pton(AF_INET, this->ip_address.c_str(), &ipv4addr);
            he = gethostbyaddr(&ipv4addr, sizeof ipv4addr, AF_INET);
            if(!he){    // ERROR
                fprintf(stderr, "Invalid IP address\n");
                exit(INTERNAL_ERROR);
            }
            this->domain_name.assign(he->h_name);
        }   

        /**
         * @brief converts domain name to ip address (IPV4 by default)
         * http://www.zedwood.com/article/cpp-dns-lookup-ipv4-and-ipv6
         */
        void hostname_to_ip(){
            struct addrinfo hints, *res, *p;
            int status, ai_family;
            char ip_address[INET6_ADDRSTRLEN];

            ai_family = AF_INET;
            memset(&hints, 0, sizeof hints);
            hints.ai_family = ai_family;
            hints.ai_socktype = SOCK_STREAM;
            
            // get the address information
            if((status = getaddrinfo(this->domain_name.c_str(), NULL, &hints, &res)) != 0){
                fprintf(stderr, "Failed to get IP address\n");
                exit(INTERNAL_ERROR);
            }

            // get the address
            for(p = res; p != NULL; p = p->ai_next){
                void *addr;
                // IPV4
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                addr = &(ipv4->sin_addr);

                // convert the IP to a string
                inet_ntop(p->ai_family, addr, ip_address, sizeof ip_address);
            }
            
            freeaddrinfo(res);

            // adding the resolved ip address
            this->ip_address.assign(ip_address);
        }

        void debug(){
            std::cout << "Domain " << domain_name << std::endl;
            std::cout << "TCP " << TCP_ports.ports << " range: " << TCP_ports.has_range << " multiple values: " << TCP_ports.multiple_values << std::endl;
            std::cout << "UDP " << UDP_ports.ports << " range: " << UDP_ports.has_range << " multiple values: " << UDP_ports.multiple_values << std::endl;
        }

};

/**
 * @brief disposes of list L
 * 
 * @param L - list containing dynamically allocated numbers of ports
 */
void DisposeList(tList *L){
    L->Last = NULL;
    while(L->First != NULL){
        tElemPtr next_element = L->First->next;
        tElemPtr to_delete = L->First;

        free(to_delete);
        L->First = next_element;
    }
}

/**
 * 
 */
void InitList(tList *L, std::string value_list){
    L->First = NULL;
    L->Last = NULL;
    std::string help_string = "";
    bool first = true;

        for(unsigned i = 0; i < (sizeof value_list - 1); i++){
            if(value_list[i] == ',' || value_list[i] == '\0'){
                tElemPtr tmp_struct_pointer = (struct tElem*) malloc(sizeof(struct tElem));
                if(tmp_struct_pointer == NULL){ // MALLOC ERROR
                    DisposeList(L);
                    exit(INTERNAL_ERROR);
                }
                
                if(first){
                    first = false;
                    L->First = tmp_struct_pointer;
                    L->Last = tmp_struct_pointer;
                    tmp_struct_pointer->next = NULL;
                }
                else{
                    L->Last->next = tmp_struct_pointer;
                    tmp_struct_pointer->next = NULL;
                    L->Last = tmp_struct_pointer;
                }

                tmp_struct_pointer->value = std::stoi(help_string);
                help_string = "";
                if(value_list[i] == '\0'){
                    break;
                }
            }
            else{
                help_string = help_string + value_list[i];
            }
        }

    }

/**
 * @brief prepares the header for final output
 * 
 * @param domain_name - name of the domain
 * @param ip_address - ip address of the domain
 */
void write_domain_header(std::string domain_name, std::string ip_address){
    std::cout << "Interesting ports on " << domain_name << " (" << ip_address << "):" << std::endl;
    std::cout << "PORT\tSTATE" << std::endl;
    return;
}

/**
 * https://www.tenouk.com/Module43b.html
 */
unsigned short csum(unsigned short *buf, int nwords){
        unsigned long sum;
        for(sum=0; nwords>0; nwords--)
                sum += *buf++;
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);
}

/**
 * 
 */
void TCP(int order_num, struct Ports real_ports){
    std::cout << order_num << "/tcp\t" << std::endl;
    return;

    int raw_socket;

    // creating the raw socket
    raw_socket = socket(AF_PACKET, SOCK_RAW, IPPROTO_TCP);
    if(raw_socket < 0){
        fprintf(stderr, "Failed to create the socket\n");
        exit(INTERNAL_ERROR);
    }
    // datagram to represent the packet
    char datagram[4096], source_ip[32];

    // IP header
    struct iphdr* iph = (struct iphdr*) datagram;

    // TCP header
    struct tcphdr* tcph = (struct tcphdr*) (datagram + sizeof(struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;
    //THIS HAS TO BE THE INTERFACE IP
    //strcpy(source_ip, real_ports.ip_address.c_str());

    // setting up the sockaddr_in
    sin.sin_family = AF_INET;
    sin.sin_port = htons(order_num);
    sin.sin_addr.s_addr = inet_addr(real_ports.ip_address.c_str());

    // clears the buffer
    memset(datagram, 0, 4096);

    // fill in the IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    // TODO
    //iph->saddr = inet_addr(source_ip);
    iph->daddr = sin.sin_addr.s_addr;

    // calculate the checksum
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

    // fill in the TCP header
    tcph->source = htons(sin.sin_addr.s_addr);
    tcph->dest = htons(order_num);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // the IP checksum
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);

    // copy it to the psh
    memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

    // calculate new checksum
    tcph->check = csum((unsigned short*)&psh, sizeof(struct pseudo_header));

    // we need to tell kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if(setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
        fprintf(stderr, "Error setting IP_HDRINCL\n");
        exit(INTERNAL_ERROR);
    }

    // close the raw socket
    close(raw_socket);

    // print the output
    std::cout << order_num << "/tcp\t" << std::endl;
}

/**
 * 
 */
void UDP(int order_num, struct Ports real_ports){
    std::cout << order_num << "/udp\t" << std::endl;
    return;

    int raw_socket;

    // creating the raw socket
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(raw_socket < 0){
        fprintf(stderr, "Failed to create the socket\n");
        exit(INTERNAL_ERROR);
    }

    // closing the raw socket
    close(raw_socket);


    std::cout << order_num << "/udp\t" << std::endl;
}

/**
 * 
 */
void process_TCP(struct Ports TCP_ports){
    if(TCP_ports.has_range){    // look at range
        // iterate throught the range
        for(int counter = TCP_ports.from; counter <= TCP_ports.to; counter++){
            TCP(counter, TCP_ports);
        }
    }
    else{                       // look at simple list of values
        if(TCP_ports.multiple_values){  // look at multiple values
            tList TCP_port_nums;
            InitList(&TCP_port_nums, TCP_ports.ports);

            // iterate and process
            tElemPtr one_element = TCP_port_nums.First;
            while(one_element != NULL){
                TCP(one_element->value, TCP_ports);
                one_element = one_element->next;
            }

            DisposeList(&TCP_port_nums);
        }
        else{                   // only one value
            TCP(std::stoi(TCP_ports.ports), TCP_ports);
        }
    }
}

/**
 * 
 */
void process_UDP(struct Ports UDP_ports){
    std::string range_del = "-";
    std::string multiple_del = ",";

    if(UDP_ports.has_range){    // look at range
        // iterate through the range
        for(int counter = UDP_ports.from; counter <= UDP_ports.to; counter++){
            UDP(counter, UDP_ports);
        }
    }
    else{                       // look at simple list of values
        if(UDP_ports.multiple_values){  // look at multiple values
            tList UDP_port_nums;
            InitList(&UDP_port_nums, UDP_ports.ports);

            // iterate and process
            tElemPtr one_elemnt = UDP_port_nums.First;
            while(one_elemnt != NULL){
                UDP(one_elemnt->value, UDP_ports);
                one_elemnt = one_elemnt->next;
            }
            
            DisposeList(&UDP_port_nums);
        }
        else{                   // only one value
            UDP(std::stoi(UDP_ports.ports), UDP_ports);
        }
    }
}


int main(int argc, char *argv[]){
    InputArgument arguments;
    arguments.parse(argc, argv);

    // write header if you can
    if(arguments.pt_tcp_flag != false || arguments.pu_udp_flag){
        write_domain_header(arguments.domain_name, arguments.ip_address);
    }
    else{
        std::cerr << "Not ports have been entered" << std::endl;
        exit(ARG_INVALID);
    }
    // TCP
    if(arguments.pt_tcp_flag){
        //process_TCP(arguments.TCP_ports);
    }
    // UDP
    if(arguments.pu_udp_flag){
        //process_UDP(arguments.UDP_ports);
    }
    
    exit(OK);
}