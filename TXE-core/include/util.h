#ifndef _UTIL_H

#define _UTIL_H
#include <vector>
#include <string>

template <typename T, typename U>
// Mapping T -> U
inline std::vector<U> fn_map(U (*fn)(T), std::vector<T> *v)
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

#endif // _UTIL_H