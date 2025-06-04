#ifndef __db
#define __db

#include <lmdb.h>
#include <iostream>
#include <cstring>
#include <errno.h>
#include <filesystem>
#include <vector>

namespace TXE
{

    struct SimpleLMDB
    {
        MDB_env *env;

        SimpleLMDB(const std::string &path)
        {
            if (!std::filesystem::create_directory(path) && !std::filesystem::is_directory(path))
            {
                throw std::runtime_error("Failed to create data directory: " + path);
            }
            if (mdb_env_create(&env))
                throw std::runtime_error("Failed to create env");
            if (mdb_env_set_maxdbs(env, 10))
                throw std::runtime_error("Failed to set maxdbs");
            if (mdb_env_open(env, path.c_str(), 0, 0664))
                throw std::runtime_error("Failed to open env");
        }

        ~SimpleLMDB()
        {
            mdb_env_close(env);
            env = nullptr;
        }

        MDB_dbi get_dbi(const std::string &name, MDB_txn *txn)
        {
            MDB_dbi dbi;
            if (mdb_dbi_open(txn, name.c_str(), MDB_CREATE, &dbi))
                throw std::runtime_error("Failed to open dbi: " + name);
            return dbi;
        }

        MDB_dbi open_existing_dbi(const std::string &name, MDB_txn *txn)
{
    MDB_dbi dbi;
    if (mdb_dbi_open(txn, name.c_str(), 0, &dbi)) 
        throw std::runtime_error("Failed to open existing dbi: " + name + ". Ensure it was created during init.");
    return dbi;
}

        void put(const std::string &table, const std::string &key, const std::string &value)
        {
            MDB_txn *txn;
            mdb_txn_begin(env, nullptr, 0, &txn);
            MDB_dbi dbi = open_existing_dbi(table, txn);

            MDB_val k{key.size(), (void *)key.data()};
            MDB_val v{value.size(), (void *)value.data()};

            if (mdb_put(txn, dbi, &k, &v, 0))
                throw std::runtime_error("Failed to put");

            mdb_txn_commit(txn);
        }

        std::string get(const std::string &table, const std::string &key)
        {
            MDB_txn *txn;
            mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
            MDB_dbi dbi = open_existing_dbi(table, txn);

            MDB_val k{key.size(), (void *)key.data()};
            MDB_val v;

            if (mdb_get(txn, dbi, &k, &v))
            {
                mdb_txn_abort(txn);
                throw std::runtime_error("Key not found");
            }

            std::string val((char *)v.mv_data, v.mv_size);
            mdb_txn_abort(txn);
            return val;
        }

        void del(const std::string &table, const std::string &key)
        {
            MDB_txn *txn;
            mdb_txn_begin(env, nullptr, 0, &txn);
            MDB_dbi dbi = open_existing_dbi(table, txn);

            MDB_val k{key.size(), (void *)key.data()};
            if (mdb_del(txn, dbi, &k, nullptr))
            {
                mdb_txn_abort(txn);
                throw std::runtime_error("Delete failed");
            }
            mdb_txn_commit(txn);
        }

        size_t count_fast(const std::string &table)
        {
            MDB_txn *txn;
            mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);

            MDB_dbi dbi = open_existing_dbi(table, txn);

            MDB_stat stat;
            if (mdb_stat(txn, dbi, &stat))
            {
                mdb_txn_abort(txn);
                throw std::runtime_error("Failed to get stats");
            }

            mdb_txn_abort(txn);
            return stat.ms_entries;
        }

        std::vector<std::string> get_all(const std::string &table)
        {
            std::vector<std::string> res;

            MDB_txn *txn;
            if (mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn))
                throw std::runtime_error("Failed to begin read transaction");

            MDB_dbi dbi = open_existing_dbi(table, txn);

            MDB_cursor *cursor;
            if (mdb_cursor_open(txn, dbi, &cursor))
            {
                mdb_txn_abort(txn);
                throw std::runtime_error("Failed to open cursor");
            }

            MDB_val key, value;
            while (mdb_cursor_get(cursor, &key, &value, MDB_NEXT) == 0)
            {
                res.emplace_back(static_cast<char *>(value.mv_data), value.mv_size);
            }

            mdb_cursor_close(cursor);
            mdb_txn_abort(txn);

            return res;
        }
    };
}

#endif
