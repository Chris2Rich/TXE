#ifndef _DB_H

#define _DB_H
#include <stdexcept>
#include <rocksdb/db.h>
#include <string>
#include <vector>
#include <memory>

void throw_db_error(rocksdb::Status status)
{
    throw std::runtime_error(status.ToString());
    return;
}

std::unique_ptr<rocksdb::DB> open_db(std::string location)
{
    rocksdb::DB *db;
    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::Open(options, std::string("/var/lib/TXE/" + location), &db);
    if (!status.ok())
    {
        throw_db_error(status);
    }

    return std::make_unique<rocksdb::DB>(db);
}

// Add to database
inline void db_add(rocksdb::DB *db, std::string *key, std::string *value)
{
    rocksdb::Status status = db->Put(rocksdb::WriteOptions(), rocksdb::Slice(key), rocksdb::Slice(value));
    if (!status.ok())
    {
        throw_db_error(status);
    }
    return;
}

// Remove from database
inline void db_remove(rocksdb::DB *db, std::string *key)
{
    rocksdb::Status status = db->Delete(rocksdb::WriteOptions(), rocksdb::Slice(key));
    if (!status.ok())
    {
        throw_db_error(status);
    }
    return;
}

inline std::string db_get(rocksdb::DB *db, std::string *key)
{
    std::string value;
    rocksdb::Status status = db->Get(rocksdb::ReadOptions(), rocksdb::Slice(key));
    if (!status.ok())
    {
        if (status.IsNotFound())
        {
            return std::string("");
        }
        else
        {
            throw_db_error(status);
        }
    }
    return value;
}

inline std::vector<std::string> db_multiget(rocksdb::DB *db, std::vector<std::string> keys)
{
    std::vector<rocksdb::Slice> slices;
    for (auto key : keys)
    {
        slices.push_back(rocksdb::Slice(key));
    }

    std::vector<std::string> values(slices.size());

    std::vector<rocksdb::Status> statuses = db->MultiGet(rocksdb::ReadOptions(), {db->DefaultColumnFamily()}, slices, &values);
    for(auto status: statuses){
        if (!status.ok())
        {
            throw_db_error(status);
        }
    }

    return values;
}
#endif // _DB_H