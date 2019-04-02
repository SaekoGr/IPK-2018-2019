#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <iostream>

#include "ipk-scan.h"

/**
 * structure Ports for input arguments
 */
struct Ports{
    std::string ports;
    bool has_range;
    bool multiple_values;
};

/**
 * @brief Class that parses input arguments and stores the necessary information for later use
 */
class InputArgument{
    public: 
        std::string domain_name;
        Ports TCP_ports;
        Ports UTP_ports;
        

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
                    counter++;
                    if(counter < argc){
                        this->check_range(&TCP_ports, argv[counter]);
                    }
                    else{
                        // ERROR
                    }
                }
                else if(strcmp(argv[counter],"-pu") == 0){
                    counter++;
                    if(counter < argc){
                        this->check_range(&UTP_ports, argv[counter]);
                    }
                    else{
                        // ERROR
                    }
                }
                else if(strcmp(argv[counter],argv[(argc-1)]) == 0){
                    domain_name.assign(argv[counter]);
                }
                else{
                    std::cerr <<"Invalid input arguments"<< std::endl;
                    exit(ARG_INVALID);
                }
                std::cout << "Argument " << argv[counter] << std::endl;
                counter++;
            }
        }

    /**
     * @brief
     */
    private:
        void check_range(struct Ports* current_ports, char* port_list){
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

            }
            else{

            }
        }
};

int main(int argc, char *argv[]){
    InputArgument arguments;
    arguments.parse(argc, argv);
    return 0;
}