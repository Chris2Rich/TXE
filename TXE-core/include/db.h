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
}

// Open database and return unique_ptr
std::unique_ptr<rocksdb::DB> open_db(const std::string& location)
{
    rocksdb::DB* db;
    rocksdb::Options options;
    options.create_if_missing = true;

    rocksdb::Status status = rocksdb::DB::Open(options, "/var/lib/TXE/" + location, &db);
    if (!status.ok())
    {
        throw_db_error(status);
    }

    return std::unique_ptr<rocksdb::DB>(db);
}

// Add to database
inline void db_add(rocksdb::DB* db, const std::string& key, const std::string& value)
{
    rocksdb::Status status = db->Put(rocksdb::WriteOptions(), rocksdb::Slice(key), rocksdb::Slice(value));
    if (!status.ok())
    {
        throw_db_error(status);
    }
}

// Remove from database
inline void db_remove(rocksdb::DB* db, const std::string& key)
{
    rocksdb::Status status = db->Delete(rocksdb::WriteOptions(), rocksdb::Slice(key));
    if (!status.ok())
    {
        throw_db_error(status);
    }
}

// Get from database
inline std::string db_get(rocksdb::DB* db, const std::string& key)
{
    std::string value;
    rocksdb::Status status = db->Get(rocksdb::ReadOptions(), rocksdb::Slice(key), &value);
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

// Multi-get
inline std::vector<std::string> db_multiget(rocksdb::DB* db, const std::vector<std::string>& keys)
{
    std::vector<rocksdb::Slice> slices;
    for (const auto& key : keys)
    {
        slices.emplace_back(key);
    }

    std::vector<std::string> values(keys.size());
    std::vector<rocksdb::Status> statuses = db->MultiGet(rocksdb::ReadOptions(), slices, &values);

    for (const auto& status : statuses)
    {
        if (!status.ok())
        {
            throw_db_error(status);
        }
    }

    return values;
}

#endif // _DB_H
