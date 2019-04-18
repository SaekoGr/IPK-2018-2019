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
#include <regex>
#include <pcap.h>
#include <csignal>


#include "ipk-scan.h"


/**
 * @brief class for parsing the input arguments
 */
class InputArgument{
    public:
        bool pt_tcp_flag = false;
        bool pu_udp_flag = false;
        bool interface_flag = false;
        bool ip_domain_input = false;
        std::string domain_name;
        std::string ip_address;
        std::string interface_ip;
        std::string interface_name;
        std::string source_ip;
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
                fprintf(stderr, "Invalid input arguments\n");
                exit(ARG_INVALID);
            }

            // must be even number of arguments
            if(argc % 2 != 0){
                fprintf(stderr, "Invalid input arguments\n");
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
                        fprintf(stderr, "Invalid input arguments\n");
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
                        this->interface_name.assign(argv[counter]);
                    }
                }
                // DOMAIN NAME | IP ADDRESS
                else{
                    if(!ip_domain_input){
                        this->resolve_ip_or_host(argv[counter]);
                        ip_domain_input = true;
                    }
                    else{
                        fprintf(stderr, "Invalid input arguments\n");
                        exit(ARG_INVALID);
                    }
                }
                counter++;
            }

            // gets the interface
            this->get_interface();

            // saves source and destination IP addresses
            TCP_ports.source_ip.assign(this->interface_ip.c_str());
            UDP_ports.source_ip.assign(this->interface_ip.c_str());
            TCP_ports.dest_ip.assign(this->ip_address.c_str());
            UDP_ports.dest_ip.assign(this->ip_address.c_str());
            TCP_ports.interface.assign(this->interface_name.c_str());
            UDP_ports.interface.assign(this->interface_name.c_str());
            //this->debug();
            //printf("SRC: %s\nDST: %s\n\n", TCP_ports.source_ip.c_str(), TCP_ports.dest_ip.c_str());
            //printf("SRC: %s\nDST: %s\n\n", UDP_ports.source_ip.c_str(), UDP_ports.dest_ip.c_str());
        }

    private:

        /**
         * @brief checks the interface input or sets the default loopback interface
         * 
         * @source http://man7.org/linux/man-pages/man3/getifaddrs.3.html
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

                    // IPv4
                if(ipv4_flag){
                    if(family == AF_INET){
                        s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                        if(s != 0){
                            fprintf(stderr, "getnameinfo failed\n");
                            exit(INTERNAL_ERROR);
                        }
                    }
                    else{
                        continue;
                    }
                }  // IPv6
                if(ipv6_flag){
                    if(family == AF_INET6){
                        s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                        if(s != 0){
                            fprintf(stderr, "getnameinfo failed\n");
                            exit(INTERNAL_ERROR);
                        }
                    }
                    else{
                        continue;
                    }
                }

                // get first loopback address                    
                if(!this->interface_flag){
                    if(!(ifa->ifa_flags & IFF_LOOPBACK)){
                        found = true;
                        this->interface_ip.assign(host);
                        this->interface_name.assign(ifa->ifa_name);
                        break;
                    }
                }
                else{   // check whether given interface exists
                    if(strcmp(this->interface_name.c_str(), ifa->ifa_name) == 0){
                        if(!(ifa->ifa_flags & IFF_LOOPBACK)){
                            found = true;
                            this->interface_ip.assign(host);
                            break;
                        }
                        else{   // should not be loopback
                            fprintf(stderr, "Input address is loopback\n");
                            exit(INTERNAL_ERROR);
                        }
                    }
                }
                
                
            }
            // free the address
            freeifaddrs(ifaddr);

            // it was not found
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
         * @param current_ports - structure for UDP/TCP with all the saved data
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
         * @brief uses regexes to check for IPv4 and IPv6
         * 
         * @value string  - that is checked
         * @return true if it is IP address
         */
        bool is_ip(char* value){
            // IPv4
            if(std::regex_match(value, std::regex("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])[.]){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"))){
                ipv4_flag = true;
                return true;
            } // IPv6
            else if(std::regex_match(value, std::regex("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])[.]){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])[.]){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"))){
                ipv6_flag = true;
                return true;
            }
            return false;
        }

        /**
         * @brief checks, whether input parameter is ip or domain
         * 
         * @param value - contains input of either ip or domain
         */
        void resolve_ip_or_host(char* value){
            if(is_ip(value)){   // value is ip_address
                this->ip_address.assign(value);
                this->ip_to_hostname();
            }
            else{               // value is domain name
                ipv4_flag = true;
                this->domain_name.assign(value);
                this->hostname_to_ip();
            }
        }

        /**
         * @brief convert ip address to domain name
         * 
         * https://beej.us/guide/bgnet/html/multi/gethostbynameman.html
         */
        void ip_to_hostname(){
            struct hostent *he;
            struct in_addr ipv4addr;
            struct in6_addr ipv6addr;

            // IPv4
            if(ipv4_flag){
                inet_pton(AF_INET, this->ip_address.c_str(), &ipv4addr);
                he = gethostbyaddr(&ipv4addr, sizeof ipv4addr, AF_INET);
            } // IPv6
            else if(ipv6_flag)
            {
                inet_pton(AF_INET6, this->ip_address.c_str(), &ipv6addr);
                he = gethostbyaddr(&ipv6addr, sizeof ipv6addr, AF_INET6);
            }

            if(!he){    // ERROR
                fprintf(stderr, "Invalid IP address\n");
                exit(INTERNAL_ERROR);
            }
            this->domain_name.assign(he->h_name);
        }   

        /**
         * @brief converts domain name to ip address (IPV4 by default)
         * 
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
 * @brief initializes list L
 * 
 * @param L - list to be dynamically allocated
 * @param value_list - 
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
 * https://stackoverflow.com/questions/51662138/tcp-syn-flood-using-raw-socket-in-ubuntu?fbclid=IwAR0lXO0WlhnHh2dx71zecLolnA-57aUgcPDsDCVkLJnL2l9eZHteotcZw6c
 */
unsigned short csum(unsigned short *ptr,int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}


void alarm_handler(int sig){
    sig = 0;
    pcap_breakloop(handle);
}

/**
 * 
 */
void TCP_IPv6(int order_num, struct Ports real_ports){
    //printf("SRC: %s\nDST: %s\n", real_ports.source_ip.c_str(), real_ports.dest_ip.c_str());
    return;

    char error_buffer[PCAP_ERRBUF_SIZE];
    unsigned char buffer[IPV6PCKT_LEN];
    struct sockaddr_in6 din;
    struct ipv6_header *ip = (struct ipv6_header*) buffer;
    //int size = sizeof(struct ipv6_header);
    struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof (struct ipv6_header));

    // clear the buffer
    memset(buffer, 0, IPV6PCKT_LEN);

    din.sin6_port = 0;
    din.sin6_family = AF_INET6;
    inet_pton(AF_INET6, real_ports.dest_ip.c_str(), &(din.sin6_addr));

    // filling in the IP header
    ip->version = 6;
    ip->traffic_class = 0;
    ip->flow_label = 0;
    ip->length = 40;
    ip->next_header = 6; // next layer is TCP
    ip->hop_limit = 64;
    inet_pton(AF_INET6, real_ports.dest_ip.c_str(), &(ip->dst));
    inet_pton(AF_INET6, real_ports.source_ip.c_str(),&(ip->src));

    // filling the TCP header
    tcph->source = htons(1234);
    tcph->dest = htons(order_num);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    int raw_socket;

    // creating the raw socket
    raw_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    if(raw_socket < 0){
        fprintf(stderr, "Failed to create the socket\n");
        exit(INTERNAL_ERROR);
    }

    // we need to tell kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if(setsockopt(raw_socket, IPPROTO_IPV6, IPV6_HDRINCL, val, sizeof(one)) < 0){
        fprintf(stderr, "Error setting IP_HDRINCL %d\n", errno);
        exit(INTERNAL_ERROR);
    }

    // send TCP packet
    unsigned short int packet_len = sizeof(struct ipv6_header) + sizeof(struct tcphdr);
    if(sendto(raw_socket, buffer, packet_len, 0, (struct sockaddr*)&din, sizeof(din)) == -1){
        fprintf(stderr, "Failed to send : %d\n", errno);
        exit(INTERNAL_ERROR);
    }

    // clean all
    close(raw_socket);

    std::cout << order_num << "/udp\t" << std::endl;
}

/**
 * https://www.tenouk.com/Module43b.html
 * https://www.devdungeon.com/content/using-libpcap-c
 */
void TCP_IPv4(int order_num, struct Ports real_ports){
    //printf("SRC: %s\nDST: %s\n", real_ports.source_ip.c_str(), real_ports.dest_ip.c_str());
    //std::cout << order_num << "/tcp\t" << std::endl;

    char error_buffer[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int ethernet_header_length = 14;
    int ip_header_length;
    int raw_socket;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    const u_char *ip_header;
    struct tcphdr *tcp_header;

    // preparing the filter string
    std::string filter_exp = "tcp and dst port 1234 and src port " + std::to_string(order_num) + " and src host " + real_ports.dest_ip + " and dst host " + real_ports.source_ip;
    //std::cout << filter_exp << std::endl;
    
    // get network number and mask
    if(pcap_lookupnet(real_ports.interface.c_str(), &net, &mask, error_buffer) == -1){
        fprintf(stderr, "Couldn't get netmask for device %s : %s\n", real_ports.interface.c_str(), error_buffer);
        net = 0;
        mask = 0;
    }

    // open handle for given interface, non-promiscuous mode, timeout 2.5 seconds
    handle = pcap_open_live(real_ports.interface.c_str(), SNAP_LEN, 0, 2500, error_buffer);
    if(handle == NULL){
        fprintf(stderr, "Couldn't open device %s\n: %s\n", real_ports.interface.c_str(), error_buffer);
        exit(INTERNAL_ERROR);
    }

    // make sure to capte on an Ethernet device
    if(pcap_datalink(handle) != DLT_EN10MB){
        fprintf(stderr, "%s is not an Ethernet\n", real_ports.interface.c_str());
        exit(INTERNAL_ERROR);
    }
    
    // creating the raw socket
    raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(raw_socket < 0){
        fprintf(stderr, "Failed to create the socket\n");
        exit(INTERNAL_ERROR);
    }
    
    // datagram to represent the packet
    char datagram[4096], source_ip[32];

    // IP header
    struct iphdr *iph = (struct iphdr*) datagram;
    // TCP header
    struct tcphdr *tcph = (struct tcphdr*) (datagram + sizeof(struct iphdr));
    struct sockaddr_in sin;
    struct pseudo_header_tcp psh;
    strcpy(source_ip, real_ports.source_ip.c_str()); // source ip

    // set the source parameters
    sin.sin_family = AF_INET;
    sin.sin_port = htons(order_num);    // destination port num
    sin.sin_addr.s_addr = inet_addr(real_ports.dest_ip.c_str());    // destination ip

    // zero out the buffer
    memset(datagram, 0, 4096);

    // filling the IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = sin.sin_addr.s_addr;

    iph->check = csum((unsigned short*) datagram, iph->tot_len >> 1);

    // filling the TCP header
    tcph->source = htons(1234);
    tcph->dest = htons(order_num);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // IP checksum
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);

    memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

    tcph->check = csum((unsigned short*)&psh, sizeof(struct pseudo_header_tcp));

    // we need to tell kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if(setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
        fprintf(stderr, "Error setting IP_HDRINCL %d\n", errno);
        exit(INTERNAL_ERROR);
    }

    // compile the filter expression
    if(pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1){
        fprintf(stderr, "Could't parse filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
        exit(INTERNAL_ERROR);
    }

    // apply the filter expression
    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp.c_str(), error_buffer);
        exit(INTERNAL_ERROR);
    }

    alarm(3);
    std::signal(SIGALRM, alarm_handler);

    // sending the packet
    if(sendto(raw_socket, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0){
        fprintf(stderr, "Error while sending %d\n", errno);
        exit(INTERNAL_ERROR);
    }

    // loop
    packet = pcap_next(handle, &packet_header);
    alarm(0);
    if(packet == NULL){ // no answer, try again
        alarm(3);
        std::signal(SIGALRM, alarm_handler);

        if(sendto(raw_socket, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0){
            fprintf(stderr, "Error while sending %d\n", errno);
            exit(INTERNAL_ERROR);
        }

        // try to catch it again
        packet = pcap_next(handle, &packet_header);
        alarm(0);
        if(packet == NULL){
            std::cout << order_num << "/tcp\tfiltered" << std::endl;
        }
        else{
            ip_header = packet + ethernet_header_length;
            ip_header_length = ((*ip_header) & 0x0F);
            ip_header_length = ip_header_length * 4;

            tcp_header = (struct tcphdr*) (packet + ethernet_header_length + ip_header_length);
            if(tcp_header->rst == 1 && tcp_header->ack == 1){
                std::cout << order_num << "/tcp\tclosed" << std::endl;
            }
            else if(tcp_header->rst == 0 && tcp_header->ack == 1){
                std::cout << order_num << "/tcp\topen" << std::endl;
            }
        }
    }
    else{
        struct ether_header *eth_header = (struct ether_header *) packet;
        ip_header = packet + ethernet_header_length;
        ip_header_length = ((*ip_header) & 0x0F);
        ip_header_length = ip_header_length * 4;

        tcp_header = (struct tcphdr*) (packet + ethernet_header_length + ip_header_length);
        if(tcp_header->rst == 1 && tcp_header->ack == 1){
            std::cout << order_num << "/tcp\tclosed" << std::endl;
        }
        else if(tcp_header->rst == 0 && tcp_header->ack == 1){
            std::cout << order_num << "/tcp\topen" << std::endl;
        }
    }

    // clean all
    pcap_freecode(&fp);
    pcap_close(handle);
    close(raw_socket);

    // print the output
    //std::cout << order_num << "/tcp\t" << std::endl;
}

/**
 * 
 */
void UDP_IPv6(int order_num, struct Ports real_ports){
    char buffer[BUFSIZ];
    const size_t len = sizeof(struct ipv6_header) + sizeof(struct udphdr);
    struct ipv6_header *ip = (struct ipv6_header*) (buffer);
}

/**
 * https://www.root.cz/clanky/sokety-a-c-raw-soket/
 */
void UDP_IPv4(int order_num, struct Ports real_ports){
    //std::cout << order_num << "/udp\t" << std::endl;
    //return;

    // IP and UDP headers
    char buffer[PCKT_LEN];
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct sockaddr_in sin;
    int raw_socket;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct bpf_program fp;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    std::string filter_exp;

    struct iphdr *iph = (struct iphdr *)buffer;
    struct udphdr *udph = (struct udphdr *)(buffer + sizeof(iphdr));

    // preparing the filter string
    filter_exp = "icmp and dst host " + real_ports.source_ip + " and src host " + real_ports.dest_ip;
    //std::cout << filter_exp << std::endl;

    // get network number and mask
    if(pcap_lookupnet(real_ports.interface.c_str(), &net, &mask, error_buffer) == -1){
        fprintf(stderr, "Couldn't get netmask for device %s : %s\n", real_ports.interface.c_str(), error_buffer);
        net = 0;
        mask = 0;
    }

    // open handle for given interface, non-promiscuous mode, timeout 2.5 seconds
    handle = pcap_open_live(real_ports.interface.c_str(), SNAP_LEN, 0, 2500, error_buffer);
    if(handle == NULL){
        fprintf(stderr, "Couldn't open device %s\n: %s\n", real_ports.interface.c_str(), error_buffer);
        exit(INTERNAL_ERROR);
    }

    // make sure to capte on an Ethernet device
    if(pcap_datalink(handle) != DLT_EN10MB){
        fprintf(stderr, "%s is not an Ethernet\n", real_ports.interface.c_str());
        exit(INTERNAL_ERROR);
    }

    // creating the raw socket
    raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(raw_socket < 0){
        fprintf(stderr, "Failed to create the socket\n");
        exit(INTERNAL_ERROR);
    }

    // filing in the IP header
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    iph->id = htons(54321);
    iph->frag_off = htons(16384);   // fragmentation is off
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(real_ports.source_ip.c_str());
    iph->daddr = inet_addr(real_ports.dest_ip.c_str());

    iph->check = htons(csum((unsigned short *)iph, sizeof(iphdr)));

    // filling in the UDP header
    udph->source = htons(1234);
    udph->dest = htons(order_num);
    udph->len = htons(sizeof(struct udphdr));
    udph->check = 0;

    sin.sin_port = htons(order_num);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(real_ports.dest_ip.c_str());


    // we need to tell kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if(setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
        fprintf(stderr, "Error setting IP_HDRINCL %d\n", errno);
        exit(INTERNAL_ERROR);
    }

    // compile the filter expression
    if(pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1){
        fprintf(stderr, "Could't parse filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
        exit(INTERNAL_ERROR);
    }

    // apply the filter expression
    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp.c_str(), error_buffer);
        exit(INTERNAL_ERROR);
    }

    // alarm
    alarm(3);
    std::signal(SIGALRM, alarm_handler);

    // sending the packet
    if(sendto(raw_socket, buffer, sizeof(struct iphdr) + sizeof(struct udphdr), 0, (struct sockaddr *) &sin, sizeof(sin)) < 0){
        fprintf(stderr, "Error while sending %d\n", errno);
        exit(INTERNAL_ERROR);
    }

    // loop
    packet = pcap_next(handle, &packet_header);
    if(packet == NULL){
        //printf("I don't have it\n");
        std::cout << order_num << "/udp\topen" << std::endl;
    }
    else{
        alarm(0);
        std::cout << order_num << "/udp\tclosed" << std::endl;
    }

    // closing the raw socket
    pcap_freecode(&fp);
    pcap_close(handle);
    close(raw_socket);


    //std::cout << order_num << "/udp\t" << std::endl;
}

/**
 * 
 */
void process_TCP(struct Ports TCP_ports){
    if(ipv4_flag){
        if(TCP_ports.has_range){    // look at range
            // iterate throught the range
            for(int counter = TCP_ports.from; counter <= TCP_ports.to; counter++){
                current_port = counter;
                TCP_IPv4(counter, TCP_ports);
            }
        }
        else{                       // look at simple list of values
            if(TCP_ports.multiple_values){  // look at multiple values
                tList TCP_port_nums;
                InitList(&TCP_port_nums, TCP_ports.ports);

                // iterate and process
                tElemPtr one_element = TCP_port_nums.First;
                while(one_element != NULL){
                    current_port = one_element->value;
                    TCP_IPv4(one_element->value, TCP_ports);
                    one_element = one_element->next;
                }

                DisposeList(&TCP_port_nums);
            }
            else{                   // only one value
                current_port = std::stoi(TCP_ports.ports);
                TCP_IPv4(std::stoi(TCP_ports.ports), TCP_ports);
            }
        }
    }
    else if(ipv6_flag){
        if(TCP_ports.has_range){    // look at range
            // iterate throught the range
            for(int counter = TCP_ports.from; counter <= TCP_ports.to; counter++){
                current_port = counter;
                TCP_IPv6(counter, TCP_ports);
            }
        }
        else{                       // look at simple list of values
            if(TCP_ports.multiple_values){  // look at multiple values
                tList TCP_port_nums;
                InitList(&TCP_port_nums, TCP_ports.ports);

                // iterate and process
                tElemPtr one_element = TCP_port_nums.First;
                while(one_element != NULL){
                    current_port = one_element->value;
                    TCP_IPv6(one_element->value, TCP_ports);
                    one_element = one_element->next;
                }

                DisposeList(&TCP_port_nums);
            }
            else{                   // only one value
                current_port = std::stoi(TCP_ports.ports);
                TCP_IPv6(std::stoi(TCP_ports.ports), TCP_ports);
            }
        }
    }
    else{
        fprintf(stderr, "Error, no ipv flag\n");
        exit(INTERNAL_ERROR);
    }
}

/**
 * 
 */
void process_UDP(struct Ports UDP_ports){
    if(ipv4_flag){
        if(UDP_ports.has_range){    // look at range
            // iterate through the range
            for(int counter = UDP_ports.from; counter <= UDP_ports.to; counter++){
                current_port = counter;
                UDP_IPv4(counter, UDP_ports);
            }
        }
        else{                       // look at simple list of values
            if(UDP_ports.multiple_values){  // look at multiple values
                tList UDP_port_nums;
                InitList(&UDP_port_nums, UDP_ports.ports);

                // iterate and process
                tElemPtr one_element = UDP_port_nums.First;
                while(one_element != NULL){
                    current_port = one_element->value;
                    UDP_IPv4(one_element->value, UDP_ports);
                    one_element = one_element->next;
                }
                
                DisposeList(&UDP_port_nums);
            }
            else{                   // only one value
                current_port = std::stoi(UDP_ports.ports);
                UDP_IPv4(std::stoi(UDP_ports.ports), UDP_ports);
            }
        }
    }
    else{
        if(UDP_ports.has_range){    // look at range
            // iterate through the range
            for(int counter = UDP_ports.from; counter <= UDP_ports.to; counter++){
                current_port = counter;
                UDP_IPv6(counter, UDP_ports);
            }
        }
        else{                       // look at simple list of values
            if(UDP_ports.multiple_values){  // look at multiple values
                tList UDP_port_nums;
                InitList(&UDP_port_nums, UDP_ports.ports);

                // iterate and process
                tElemPtr one_element = UDP_port_nums.First;
                while(one_element != NULL){
                    current_port = one_element->value;
                    UDP_IPv6(one_element->value, UDP_ports);
                    one_element = one_element->next;
                }
                
                DisposeList(&UDP_port_nums);
            }
            else{                   // only one value
                current_port = std::stoi(UDP_ports.ports);
                UDP_IPv6(std::stoi(UDP_ports.ports), UDP_ports);
            }
        }
    }
}

/**
 * @brief main function calls arguments class and then call appropriate functions for TCP/UDP
 */
int main(int argc, char *argv[]){
    InputArgument arguments;
    arguments.parse(argc, argv);

    // write header if you can
    if(arguments.pt_tcp_flag != false || arguments.pu_udp_flag){
        write_domain_header(arguments.domain_name, arguments.ip_address);
    }
    else{
        fprintf(stderr, "Not ports have been entered\n");
        exit(ARG_INVALID);
    }
    // TCP
    if(arguments.pt_tcp_flag){
        process_TCP(arguments.TCP_ports);
    }
    // UDP
    if(arguments.pu_udp_flag){
        process_UDP(arguments.UDP_ports);
    }
    
    exit(OK);
}