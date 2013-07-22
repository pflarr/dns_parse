#include <arpa/inet.h>
#include "dns_parse.h"

#ifndef __BP_NETWORK
#define __BP_NETWORK

// Ethernet data struct.
typedef struct {
    // The MAC's can probably be removed from this, as they aren't used
    // outside of the ethernet parser.
    uint8_t dstmac[6];
    uint8_t srcmac[6];
    uint16_t ethtype;
} eth_info;

#define IPv4 0x04
#define IPv6 0x06

// IP address container that is IP version agnostic.
// The IPvX_MOVE macros handle filling these with packet data correctly.
typedef struct ip_addr {
    // Should always be either 4 or 6.
    uint8_t vers;
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

// Compare two IP addresses.
#define IP_CMP(ipA, ipB) ((ipA.vers == ipB.vers) &&\
                          (ipA.vers == IPv4 ? \
                            ipA.addr.v4.s_addr == ipB.addr.v4.s_addr : \
                ((ipA.addr.v6.s6_addr32[0] == ipB.addr.v6.s6_addr32[0]) && \
                 (ipA.addr.v6.s6_addr32[1] == ipB.addr.v6.s6_addr32[1]) && \
                 (ipA.addr.v6.s6_addr32[2] == ipB.addr.v6.s6_addr32[2]) && \
                 (ipA.addr.v6.s6_addr32[3] == ipB.addr.v6.s6_addr32[3])) \
                 ))

// Basic network layer information.
typedef struct {
    ip_addr src;
    ip_addr dst;
    uint32_t length;
    uint8_t proto;
} ip_info;

// IP fragment information.
typedef struct ip_fragment {
    uint32_t id;
    ip_addr src;
    ip_addr dst;
    uint32_t start;
    uint32_t end;
    uint8_t * data;
    uint8_t islast; 
    struct ip_fragment * next;
    struct ip_fragment * child; 
} ip_fragment;

#define UDP 0x11
#define TCP 0x06

// Transport information.
typedef struct {
    uint16_t srcport;
    uint16_t dstport;
    // Length of the payload.
    uint16_t length;
    uint8_t transport; 
} transport_info;

// Parsers all follow the same basic pattern. They take the position in
// the packet data, the packet data pointer, the header, and an object
// to fill out. They return the position of the first byte of their payload.
// On error, they report the error and return 0.
// Exceptions are noted.

// No pos is passed, since we always start at 0.
uint32_t eth_parse(struct pcap_pkthdr *, uint8_t *, eth_info *, config *);
// This mucks with the eth data, rather than having data of its own.
uint32_t mpls_parse(uint32_t, struct pcap_pkthdr *, 
                    uint8_t *, eth_info *);
uint32_t udp_parse(uint32_t, struct pcap_pkthdr *, uint8_t *, 
                   transport_info *, config *);
// The ** to the packet data is passed, instead of the data directly.
// They may set the packet pointer to a new data array.
// On error, the packet pointer is set to NULL.
uint32_t ipv4_parse(uint32_t, struct pcap_pkthdr *, 
                    uint8_t **, ip_info *, config *);
uint32_t ipv6_parse(uint32_t, struct pcap_pkthdr *,
                    uint8_t **, ip_info *, config *);

// Add the ip_fragment object to our lists of fragments. If a fragment is
// complete, returns the completed fragment object.
ip_fragment * ip_frag_add(ip_fragment *, config *);

// Frees all fragment objects.
void ip_frag_free(config *);

// Convert an ip struct to a string. The returned buffer is internal, 
// and need not be freed. 
char * iptostr(ip_addr *);
#endif
