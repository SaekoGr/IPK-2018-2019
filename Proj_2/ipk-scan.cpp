/**
 * Project no. 2 for IPK
 * Name: ipk-scan.cpp
 * Language: C++
 * Author: Sabína Gregušová (xgregu02)
 */

#include "ipk-scan.h"

/**
 * @brief class for parsing the input arguments
 */
class InputArgument{
    public:
        // necessary variables
        bool pt_tcp_flag = false;
        bool pu_udp_flag = false;
        bool interface_flag = false;
        bool ip_domain_input = false;
        std::string domain_name;
        std::string ip_address;
        std::string interface_ip;
        std::string interface_name;
        std::string source_ip;
        // structure for both TCP and UDP
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

            // saves all necessary information
            TCP_ports.source_ip.assign(this->interface_ip.c_str());
            UDP_ports.source_ip.assign(this->interface_ip.c_str());
            TCP_ports.dest_ip.assign(this->ip_address.c_str());
            UDP_ports.dest_ip.assign(this->ip_address.c_str());
            TCP_ports.interface.assign(this->interface_name.c_str());
            UDP_ports.interface.assign(this->interface_name.c_str());
            TCP_ports.domain_name.assign(this->domain_name.c_str());
            UDP_ports.domain_name.assign(this->domain_name.c_str());
        }

    private:

        /**
         * @brief checks the interface input or sets the default nonloopback interface
         * 
         * @source http://man7.org/linux/man-pages/man3/getifaddrs.3.html
         * @author couldn't resolve
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
                        found = true;
                        this->interface_ip.assign(host);
                        break;
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
            // source : http://ipregex.com/
            if(std::regex_match(value, std::regex("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])[.]){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"))){
                ipv4_flag = true;
                return true;
            } // IPv6
            // source : https://www.phpliveregex.com/learn/system-administration/how-to-match-ip-addresses/
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
         * @source https://beej.us/guide/bgnet/html/multi/gethostbynameman.html
         * @author Brian "Beej Jorgensen" Hall
         * @version 3.0.21
         * @published June 8, 2016
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
         * @source http://www.zedwood.com/article/cpp-dns-lookup-ipv4-and-ipv6
         * @author couldn't resolve
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
};

/**
 * @brief disposes of list L
 * 
 * @param L - list containing dynamically allocated numbers of ports
 * 
 * @source https://github.com/SaekoGr/IAL-2018-2019/blob/master/ial_2018_du1/c201/c201.c
 * @author Sabína Gregušová (xgregu02) for IAL
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
 * @param value_list - list of ports to be scanned
 * 
 * @source https://github.com/SaekoGr/IAL-2018-2019/blob/master/ial_2018_du1/c201/c201.c
 * @author Sabína Gregušová (xgregu02) for IAL
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
 * @brief oficial check sum for headers (IPv4)
 * 
 * @param ptr
 * @param nbytes
 * @return unsigned short
 * 
 * @source https://stackoverflow.com/questions/51662138/tcp-syn-flood-using-raw-socket-in-ubuntu?fbclid=IwAR0lXO0WlhnHh2dx71zecLolnA-57aUgcPDsDCVkLJnL2l9eZHteotcZw6c
 * @author: zx485
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

/**
 * @brief function for breaking the loop
 * 
 * @sig number of second for waiting
 */
void alarm_handler(int sig){
    sig = 0;
    pcap_breakloop(handle);
}

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
void TCP_IPv6(int order_num, struct Ports real_ports){

    int i, sd, status, frame_length, raw_socket, bytes, *tcp_flags;
    char *interface, *target, *src_ip, *dst_ip;
    struct ip6_hdr iphdr;
    struct tcphdr tcphdr;
    uint8_t *src_mac, *dst_mac, *ether_frame;
    struct addrinfo hints, *res;
    struct sockaddr_in6 *ipv6;
    struct sockaddr_ll device;
    struct ifreq ifr;
    void *tmp;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char error_buffer[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int ethernet_header_length = 14;
    int ip_header_length;
    const u_char *ip_header;
    struct tcphdr *tcp_header;

    // preparing the filter string
    std::string filter_exp = "tcp and dst port 1234 and src port " + std::to_string(order_num) + " and src host " + real_ports.dest_ip + " and dst host " + real_ports.source_ip;
    
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

    // Allocate memory for various arrays.
    src_mac = allocate_ustrmem (6);
    dst_mac = allocate_ustrmem (6);
    ether_frame = allocate_ustrmem (IP_MAXPACKET);
    interface = allocate_strmem (40);
    target = allocate_strmem (INET6_ADDRSTRLEN);
    src_ip = allocate_strmem (INET6_ADDRSTRLEN);
    dst_ip = allocate_strmem (INET6_ADDRSTRLEN);
    tcp_flags = allocate_intmem (8);

    // Interface to send packet through.
    strcpy (interface, real_ports.interface.c_str());

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl() ");
        exit(INTERNAL_ERROR);
    }

    // Use ioctl() to look up interface name and get its MAC address.
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror ("ioctl() failed to get source MAC address ");
        exit(INTERNAL_ERROR);
    }
    close (sd);

    // Copy source MAC address.
    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    memset (&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex (real_ports.interface.c_str())) == 0) {
        perror ("if_nametoindex() failed to obtain interface index ");
        exit (EXIT_FAILURE);
    }

    // Set destination MAC address: you need to fill these out
    dst_mac[0] = 0xff;
    dst_mac[1] = 0xff;
    dst_mac[2] = 0xff;
    dst_mac[3] = 0xff;
    dst_mac[4] = 0xff;
    dst_mac[5] = 0xff;

    // Source IPv6 address: you need to fill this out
    strcpy (src_ip, real_ports.source_ip.c_str());

    // Destination URL or IPv6 address: you need to fill this out
    strcpy (target, real_ports.domain_name.c_str());

    // Fill out hints for getaddrinfo().
    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Resolve target using getaddrinfo().
    if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
        fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
        exit (EXIT_FAILURE);
    }
    ipv6 = (struct sockaddr_in6 *) res->ai_addr;
    tmp = &(ipv6->sin6_addr);
    if (inet_ntop (AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL) {
        status = errno;
        fprintf (stderr, "inet_ntop() failed.\nError message: %s\n", strerror (status));
        exit (EXIT_FAILURE);
    }
    freeaddrinfo (res);

    // fill out sockaddr_ll
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, src_mac, 6* sizeof(uint8_t));
    device.sll_halen = 6;

    // IPv6 header
    // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
    // Payload length (16 bits): TCP header
    iphdr.ip6_plen = htons (TCP_HDRLEN);
    // Next header (8 bits): 6 for TCP
    iphdr.ip6_nxt = IPPROTO_TCP;
    // Hop limit (8 bits): default to maximum value
    iphdr.ip6_hops = 255;


    // Source IPv6 address (128 bits)
    if ((status = inet_pton (AF_INET6, src_ip, &(iphdr.ip6_src))) != 1) {
        fprintf (stderr, "inet_pton() failed.\nError message: %s\n", strerror (status));
        exit (EXIT_FAILURE);
    }

    // Destination IPv6 address (128 bits)
    if ((status = inet_pton (AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1) {
        fprintf (stderr, "inet_pton() failed.\nError message: %s\n", strerror (status));
        exit (EXIT_FAILURE);
    }

    // TCP header
    // Source port number (16 bits)
    tcphdr.th_sport = htons (1234);
    // Destination port number (16 bits)
    tcphdr.th_dport = htons (order_num);
    // Sequence number (32 bits)
    tcphdr.th_seq = htonl (0);
    // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
    tcphdr.th_ack = htonl (0);
    // Reserved (4 bits): should be 0
    tcphdr.th_x2 = 0;
    // Data offset (4 bits): size of TCP header in 32-bit words
    tcphdr.th_off = TCP_HDRLEN / 4;
    // Flags (8 bits)
    // FIN flag (1 bit)
    tcp_flags[0] = 0;
    // SYN flag (1 bit): set to 1
    tcp_flags[1] = 1;
    // RST flag (1 bit)
    tcp_flags[2] = 0;
    // PSH flag (1 bit)
    tcp_flags[3] = 0;
    // ACK flag (1 bit)
    tcp_flags[4] = 0;
    // URG flag (1 bit)
    tcp_flags[5] = 0;
    // ECE flag (1 bit)
    tcp_flags[6] = 0;
    // CWR flag (1 bit)
    tcp_flags[7] = 0;

    tcphdr.th_flags = 0;
    for (i=0; i<8; i++) {
        tcphdr.th_flags += (tcp_flags[i] << i);
    }

    // Window size (16 bits)
    tcphdr.th_win = htons (65535);
    // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
    tcphdr.th_urp = htons (0);
    // TCP checksum (16 bits)
    tcphdr.th_sum = tcp6_checksum (iphdr, tcphdr);

    // Fill out ethernet frame header.

    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header)
    frame_length = 6 + 6 + 2 + IP6_HDRLEN + TCP_HDRLEN;

    // Destination and Source MAC addresses
    memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
    memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

    // Next is ethernet type code (ETH_P_IPV6 for IPv6).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_IPV6 / 256;
    ether_frame[13] = ETH_P_IPV6 % 256;

    // Next is ethernet frame data (IPv6 header + TCP header).

    // IPv6 header
    memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof (uint8_t));
    // TCP header
    memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
    
    // creating the raw socket
    raw_socket = socket(PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
    if(raw_socket < 0){
        fprintf(stderr, "Failed to create the socket\n");
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

    // Send ethernet frame to socket.
    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
        perror ("sendto() failed");
        exit (EXIT_FAILURE);
    }

    // loop
    packet = pcap_next(handle, &packet_header);
    alarm(0);
    if(packet == NULL){ // no answer, try again
        alarm(3);
        std::signal(SIGALRM, alarm_handler);

        // Send ethernet frame to socket.
        if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
            perror ("sendto() failed");
            exit (EXIT_FAILURE);
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

    // close socket
    pcap_freecode(&fp);
    pcap_close(handle);
    close(raw_socket);

    // Free allocated memory.
    free (src_mac);
    free (dst_mac);
    free (ether_frame);
    free (interface);
    free (target);
    free (src_ip);
    free (dst_ip);
    free (tcp_flags);

}

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
 * @source https://stackoverflow.com/questions/51662138/tcp-syn-flood-using-raw-socket-in-ubuntu?fbclid=IwAR0lXO0WlhnHh2dx71zecLolnA-57aUgcPDsDCVkLJnL2l9eZHteotcZw6c
 * @author zx485
 * 
 * Catching the response pakets
 * @source https://www.devdungeon.com/content/using-libpcap-c
 * @author couldn't resolve
 * 
 */
void TCP_IPv4(int order_num, struct Ports real_ports){

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
}


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
void UDP_IPv6(int order_num, struct Ports real_ports){

    int status, datalen, frame_length, sd, bytes, raw_socket;
    char *interface, *target, *src_ip, *dst_ip;
    struct ip6_hdr iphdr;
    struct udphdr udphdr;
    uint8_t *data, *src_mac, *dst_mac, *ether_frame;
    struct addrinfo hints, *res;
    struct sockaddr_in6 *ipv6;
    struct sockaddr_ll device;
    struct ifreq ifr;
    void *tmp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct bpf_program fp;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    std::string filter_exp;
    char error_buffer[PCAP_ERRBUF_SIZE];

    // preparing the filter string
    filter_exp = "icmp and dst host " + real_ports.source_ip + " and src host " + real_ports.dest_ip;

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

    // Allocate memory for various arrays.
    src_mac = allocate_ustrmem (6);
    dst_mac = allocate_ustrmem (6);
    data = allocate_ustrmem (IP_MAXPACKET);
    ether_frame = allocate_ustrmem (IP_MAXPACKET);
    interface = allocate_strmem (40);
    target = allocate_strmem (INET6_ADDRSTRLEN);
    src_ip = allocate_strmem (INET6_ADDRSTRLEN);
    dst_ip = allocate_strmem (INET6_ADDRSTRLEN);

    strcpy(interface, real_ports.interface.c_str());

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl() ");
        exit(INTERNAL_ERROR);
    }

    // Use ioctl() to look up interface name and get its MAC address.
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror ("ioctl() failed to get source MAC address ");
        exit(INTERNAL_ERROR);
    }
    close (sd);

    // Copy source MAC address.
    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    memset (&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index ");
        exit (INTERNAL_ERROR);
    }

    // Set destination MAC address: you need to fill these out
    dst_mac[0] = 0xff;
    dst_mac[1] = 0xff;
    dst_mac[2] = 0xff;
    dst_mac[3] = 0xff;
    dst_mac[4] = 0xff;
    dst_mac[5] = 0xff;

    // Source IPv6 address: you need to fill this out
    strcpy (src_ip, real_ports.source_ip.c_str());

    // Destination URL or IPv6 address: you need to fill this out
    strcpy (target, real_ports.domain_name.c_str());

    // Fill out hints for getaddrinfo().
    memset (&hints, 0, sizeof (hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Resolve target using getaddrinfo().
    if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
        fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
        exit (EXIT_FAILURE);
    }
    ipv6 = (struct sockaddr_in6 *) res->ai_addr;
    tmp = &(ipv6->sin6_addr);
    if (inet_ntop (AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL) {
        status = errno;
        fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }
    freeaddrinfo (res);

    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
    device.sll_halen = 6;

    // UDP data
    datalen = 4;
    data[0] = 'T';
    data[1] = 'e';
    data[2] = 's';
    data[3] = 't';

    // IPv6 header
    // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
    // Payload length (16 bits): UDP header + UDP data
    iphdr.ip6_plen = htons (UDP_HDRLEN + datalen);
    // Next header (8 bits): 17 for UDP
    iphdr.ip6_nxt = IPPROTO_UDP;
    // Hop limit (8 bits): default to maximum value
    iphdr.ip6_hops = 255;

    // Source IPv6 address (128 bits)
    if ((status = inet_pton (AF_INET6, src_ip, &(iphdr.ip6_src))) != 1) {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }

    // Destination IPv6 address (128 bits)
    if ((status = inet_pton (AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1) {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }

    // UDP header
    // Source port number (16 bits): pick a number
    udphdr.source = htons (1234);
    // Destination port number (16 bits): pick a number
    udphdr.dest = htons (order_num);
    // Length of UDP datagram (16 bits): UDP header + UDP data
    udphdr.len = htons (UDP_HDRLEN + datalen);
    // UDP checksum (16 bits)
    udphdr.check = udp6_checksum (iphdr, udphdr, data, datalen);

    // Fill out ethernet frame header.

    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + UDP header + UDP data)
    frame_length = 6 + 6 + 2 + IP6_HDRLEN + UDP_HDRLEN + datalen;

    // Destination and Source MAC addresses
    memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
    memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

    // Next is ethernet type code (ETH_P_IPV6 for IPv6).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_IPV6 / 256;
    ether_frame[13] = ETH_P_IPV6 % 256;

    // Next is ethernet frame data (IPv6 header + UDP header + UDP data).

    // IPv6 header
    memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof (uint8_t));

    // UDP header
    memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &udphdr, UDP_HDRLEN * sizeof (uint8_t));

    // UDP data
    memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN + UDP_HDRLEN, data, datalen * sizeof (uint8_t));


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

    // Submit request for a raw socket descriptor.
    if ((raw_socket = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed ");
        exit (EXIT_FAILURE);
    }

    // alarm
    alarm(3);
    std::signal(SIGALRM, alarm_handler);

    // Send ethernet frame to socket.
    if ((bytes = sendto (raw_socket, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
        perror ("sendto() failed");
        exit (EXIT_FAILURE);
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

    // close socket
    pcap_freecode(&fp);
    pcap_close(handle);
    close(raw_socket);

    // Free allocated memory.
    free (src_mac);
    free (dst_mac);
    free (data);
    free (ether_frame);
    free (interface);
    free (target);
    free (src_ip);
    free (dst_ip);

}

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

}

/**
 * @brief goes through the port range and sends it to process 
 * 
 * @param TCP_ports structure that contains necessary information for TCP protocol
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
 * @brief goes through the port range and sends it to process 
 * 
 * @param UDP_ports structure that contains necessary information for UDP protocol
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
    if(arguments.pt_tcp_flag != false || arguments.pu_udp_flag != false){
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
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

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
char *
allocate_strmem (int len)
{
  char *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

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
uint8_t *
allocate_ustrmem (int len)
{
  uint8_t *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

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

int *
allocate_intmem (int len)
{
  int* tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}

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
uint16_t
tcp6_checksum (struct ip6_hdr iphdr, struct tcphdr tcphdr)
{
  uint32_t lvalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src, sizeof (iphdr.ip6_src));
  ptr += sizeof (iphdr.ip6_src);
  chksumlen += sizeof (iphdr.ip6_src);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst, sizeof (iphdr.ip6_dst));
  ptr += sizeof (iphdr.ip6_dst);
  chksumlen += sizeof (iphdr.ip6_dst);

  // Copy TCP length to buf (32 bits)
  lvalue = htonl (sizeof (tcphdr));
  memcpy (ptr, &lvalue, sizeof (lvalue));
  ptr += sizeof (lvalue);
  chksumlen += sizeof (lvalue);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  return checksum ((uint16_t *) buf, chksumlen);
}


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
uint16_t
udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src.s6_addr);
  chksumlen += sizeof (iphdr.ip6_src.s6_addr);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy UDP length into buf (32 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }
  return checksum ((uint16_t *) buf, chksumlen);
}