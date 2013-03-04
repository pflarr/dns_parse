//Structs and defines for all of the low level protocols parsed.

#ifndef __DP_PROTOCOLS
#define __DP_PROTOCOLS

#include <arpa/inet.h>
#include <pcap.h>

typedef struct {
    u_char dstmac[6];
    u_char srcmac[6];
    u_short ethtype;
} eth_info;

#define IPv4 0x04
#define IPv6 0x06

typedef struct ip_addr {
    u_char vers;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } addr;
} ip_addr;
// Move IPv4 addr at pointer P into ip object D, and set it's type.
#define IPv4_MOVE(D, P) D.addr.v4.s_addr = *(in_addr_t *)(P); \
                        D.vers = IPv4;
// Move IPv6 addr at pointer P into ip object D, and set it's type.
#define IPv6_MOVE(D, P) memcpy(D.addr.v6.s6_addr, P, 16); D.vers = IPv6;

// Convert an ip struct into a str. Like NTOA, this uses a single
// buffer, so freeing it need not be freed, but it can only be used once
// per statement.
char IP_STR_BUFF[INET6_ADDRSTRLEN];
// Convert an ip struct to a string. The returned buffer is internal, 
// and need not be freed. 
inline char * iptostr(ip_addr *);

// Compare two IP addresses.
#define IP_CMP(ipA, ipB) ((ipA.vers == ipB.vers) &&\
                          (ipA.vers == IPv4 ? \
                            ipA.addr.v4.s_addr == ipB.addr.v4.s_addr : \
                ((ipA.addr.v6.s6_addr32[0] == ipB.addr.v6.s6_addr32[0]) && \
                 (ipA.addr.v6.s6_addr32[1] == ipB.addr.v6.s6_addr32[1]) && \
                 (ipA.addr.v6.s6_addr32[2] == ipB.addr.v6.s6_addr32[2]) && \
                 (ipA.addr.v6.s6_addr32[3] == ipB.addr.v6.s6_addr32[3])) \
                 ))

typedef struct {
    ip_addr src;
    ip_addr dst;
    bpf_u_int32 length;
    u_char proto;
} ip_info;

typedef struct ip_fragment {
    bpf_u_int32 id;
    ip_addr src;
    ip_addr dst;
    bpf_u_int32 start;
    bpf_u_int32 end;
    u_char * data;
    u_char islast; 
    struct ip_fragment * next;
    struct ip_fragment * child; 
} ip_fragment;

#define UDP 0x11
#define TCP 0x06

typedef struct {
    u_short srcport;
    u_short dstport;
    u_short length;
    u_char transport; 
} transport_info;

typedef struct tcp_info {
    struct timeval ts;
    ip_addr src;
    ip_addr dst;
    u_short srcport;
    u_short dstport;
    bpf_u_int32 sequence;
    bpf_u_int32 ack_num;
    // The length of the data portion.
    bpf_u_int32 len;
    u_char syn;
    u_char ack;
    u_char fin;
    u_char rst;
    u_char * data;
    // The next item in the list of tcp sessions.
    struct tcp_info * next_sess;
    // These are for connecting all the packets in a session. The session
    // pointers above will always point to the most recent packet.
    // next_pkt and prev_pkt make chronological sense (next_pkt is always 
    // more recent, and prev_pkt is less), we just hold the chain by the tail.
    struct tcp_info * next_pkt;
    struct tcp_info * prev_pkt;
} tcp_info;

#endif
