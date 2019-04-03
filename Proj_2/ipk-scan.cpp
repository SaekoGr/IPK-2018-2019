#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <iostream>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "ipk-scan.h"

/**
 * structure Ports for input arguments
 */
struct Ports{
    std::string ports;
    bool has_range;
    bool multiple_values;
    int from = 0;
    int to = 0;
};

/**
 * @brief Class that parses input arguments and stores the necessary information for later use
 */
class InputArgument{
    public:
        bool pt_tcp_flag = false;
        bool pu_udp_flag = false; 
        std::string domain_name;
        std::string ip_address;
        Ports TCP_ports;
        Ports UDP_ports;
        

        void parse(int argc, char *argv[]){
            int counter = 1;

            // too many or too few arguments
            if(argc == 1 || argc > 6){
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
                }
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
                }           // DOMAIN NAME | IP ADDRESS
                else if(strcmp(argv[counter],argv[(argc-1)]) == 0){
                    this->resolve_ip_or_host(argv[counter]);
                }
                else{       // ERROR
                    std::cerr <<"Invalid input arguments"<< std::endl;
                    exit(ARG_INVALID);
                }
                counter++;
            }

            this->debug();
        }


    /**
     * @brief
     */
    private:


        /**
         * 
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

            }
            // cannot be negative
            if(std::stoi(from) < 0){

            }

            return std::stoi(from);
        }

        /**
         * 
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

            }
            // cannot be negative
            if(std::stoi(to) < 0){

            }

            return std::stoi(to);

        }

        /**
         * 
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
         * 
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
         * 
         */
        void ip_to_hostname(){
            struct sockaddr_in saGNI;
            char hostname[NI_MAXHOST];
            char servInfo[NI_MAXSERV];
            u_short port = 27015;
            int dwRetval;

            saGNI.sin_family = AF_INET;
            saGNI.sin_addr.s_addr = inet_addr(this->ip_address.c_str());
            saGNI.sin_port = htons(port);
            
            dwRetval = getnameinfo((struct sockaddr *) &saGNI, sizeof(struct sockaddr), hostname, NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);

            this->domain_name.assign(hostname);
        }   

        /**
         * 
         */
        void hostname_to_ip(){
            struct addrinfo hints, *servinfo, *p;
            struct sockaddr_in *h;
            int rv;
            
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;

            if((rv = getaddrinfo(this->domain_name.c_str(), "http", &hints, &servinfo)) != 0){
                fprintf(stderr, "Get address error\n");
                exit(INTERNAL_ERROR);
            }

            for(p = servinfo; p != NULL; p = p->ai_next){
                h = (struct sockaddr_in *) p->ai_addr;
                this->ip_address.assign(inet_ntoa(h->sin_addr));
            }
            freeaddrinfo(servinfo);
        }

        void debug(){
            std::cout << "Domain " << domain_name << std::endl;
            std::cout << "TCP " << TCP_ports.ports << " range: " << TCP_ports.has_range << " multiple values: " << TCP_ports.multiple_values << std::endl;
            std::cout << "UDP " << UDP_ports.ports << " range: " << UDP_ports.has_range << " multiple values: " << UDP_ports.multiple_values << std::endl;
        }
};

/**
 * 
 */
void write_domain_header(std::string domain_name, std::string ip_address){
    std::cout << "Interesting ports on " << domain_name << " (" << ip_address << "):" << std::endl;
    std::cout << "PORT\tSTATE" << std::endl;
    return;
}

/**
 * 
 */
void check_TCP(struct Ports TCP_ports){
    if(TCP_ports.has_range){    // look at range
        // iterate throught the range
        for(int counter = TCP_ports.from; counter <= TCP_ports.to; counter++){
            std::cout << counter << std::endl;
        }
    }
    else{                       // look at simple list of values
        if(TCP_ports.multiple_values){  // look at multiple values

        }
        else{                   // only one value

        }
    }
}

/**
 * 
 */
void check_UDP(struct Ports UDP_ports){
    std::string range_del = "-";
    std::string multiple_del = ",";

    if(UDP_ports.has_range){    // look at range
        // iterate through the range
        for(int counter = UDP_ports.from; counter <= UDP_ports.to; counter++){
            std::cout << counter << std::endl;
        }
    }
    else{                       // look at simple list of values
        if(UDP_ports.multiple_values){  // look at multiple values

        }
        else{                   // only one value

        }
    }
}

/**
 * 
 */
int main(int argc, char *argv[]){
    InputArgument arguments;
    arguments.parse(argc, argv);
    
    write_domain_header(arguments.domain_name, arguments.ip_address);
    if(arguments.pt_tcp_flag){
        check_TCP(arguments.TCP_ports);
    }
    if(arguments.pu_udp_flag){
        check_UDP(arguments.UDP_ports);
    }
    
    exit(OK);
}