#ifndef _UTIL_H

#define _UTIL_H
#include <vector>
#include <string>
#include <iomanip>

template <typename T, typename U>
// Mapping T -> U
inline std::vector<U> fn_map(U (fn)(T), std::vector<T> *v)
{
    std::vector<U> res(v->size());
    for(int i = 0; i < v->size(); i++){
        res[i] = fn((*v)[i]);
    }

    return res;
}

std::string uchar_to_string(unsigned char* v){
    std::string res;
    for(int i = 0; i < 64; i++){
        res += v[i];
    }
    return res;
}

std::string uchar_to_hex(const unsigned char *arr, size_t length)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i)
    {
        oss << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(arr[i]));
    }
    return oss.str();
}

#endif // _UTIL_H