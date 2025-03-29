#ifndef _UTIL_H

#define _UTIL_H
#include <vector>
#include <memory>

template <typename T, typename U>
// Mapping T -> U
std::unique_ptr<std::vector<U>> fn_map(U (*fn)(T), std::vector<T> *v)
{
    std::vector<U> res(v->size());
    for(auto x: *V){
        
    }

    return std::unique_ptr<std::vector<U>>(res);
}

#endif // _UTIL_H