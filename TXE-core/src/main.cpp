#include "/workspaces/ecc/TXE-core/include/tx.h"
#include "/workspaces/ecc/TXE-core/include/block.h"

int main(){
    block bloc;
    tx a(61);
    tx b(62);
    tx c(63);
    tx d(64);
    unsigned char res[64];
    bloc.tx_list = {a,b,c,d};
    bloc.create_merkle_root(res);
    return 0;
}