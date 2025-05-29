#include "wallet.cpp"
#include "tx.cpp"
#include "block.cpp"
#include "db.cpp"

#include <iostream>
#include <string>

int main(int argc, char *argv[])
{
    if (std::string(argv[1]) == "init")
    {
        TXE::SimpleLMDB db("./lmdb_data");
        MDB_txn *txn;
        if (mdb_txn_begin(db.env, nullptr, 0, &txn))
            throw std::runtime_error("Failed to begin init transaction");

        db.get_dbi("blocks", txn);
        db.get_dbi("key_images", txn);
        db.get_dbi("transactions", txn);
        db.get_dbi("outputs", txn);
        db.get_dbi("output_indexes", txn);

        if (mdb_txn_commit(txn))
            throw std::runtime_error("Failed to commit init transaction");

        std::cout << "LMDB initialized with tables: blocks, key_images, ring_members, transactions, outputs" << std::endl;
    }
    if (std::string(argv[1]) == "wallet")
    {
        // wallet create "filepath"
        if (std::string(argv[2]) == "create")
        {

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