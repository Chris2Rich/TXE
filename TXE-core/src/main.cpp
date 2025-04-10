#include <iostream>

#include "tx.h"
#include "block.h"
#include "util.h"

int main()
{
    block bloc;
    tx a(5);
    bloc.tx_list = {a};

    header heder;
    bloc.create_merkle_root(heder.merkel_root);
    heder.version = 1;
    heder.create_block_id(heder.id);

    std::cout << uchar_to_hex(heder.id, 64);
    
    return 0;
}