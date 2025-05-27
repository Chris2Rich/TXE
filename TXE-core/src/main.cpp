#include "wallet.cpp"
#include "tx.cpp"
#include "block.cpp"
#include "db.cpp"

#include <iostream>
#include <string>

int main(int argc, char* argv[]){
    if(std::string(argv[1]) == "wallet"){
        //wallet create "filepath"
        if(std::string(argv[2]) == "create"){

            std::string pass;
            std::cout << "Input Password: ";
            std::cin >> pass;
            std::cout << std::endl;

            TXE::WalletKeys k;
            k.generate();
            k.save(std::string(argv[3]), pass);
            std::cout << "wallet keys saved at: " << std::string(argv[3]) << std::endl;
        }
    }
    return 0;
}