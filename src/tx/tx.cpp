struct tx{
    unsigned char txid[2]; //functions as a nonce
    //inputs
    //outputs

    const unsigned char* stringify(){
        const unsigned char* res = (const unsigned char*)"Test"; 
        return res;
    }
};