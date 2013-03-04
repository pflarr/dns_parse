#include "protocols.h"

// Convert an ip struct to a string. The returned buffer is internal, 
// and need not be freed. 
inline char * iptostr(ip_addr * ip) {
    if (ip->vers == IPv4) {
        inet_ntop(AF_INET, (const void *) &(ip->addr.v4),
                  IP_STR_BUFF, INET6_ADDRSTRLEN);
    } else { // IPv6
        inet_ntop(AF_INET6, (const void *) &(ip->addr.v6),
                  IP_STR_BUFF, INET6_ADDRSTRLEN);
    }
    return IP_STR_BUFF;
}
