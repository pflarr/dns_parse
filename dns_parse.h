// Structs and defines common to most of DNS parse.

#ifndef __DP_MAIN
#define __DP_MAIN

#include <pcap.h>
// For standard int type declarations.
#include <stdint.h>

// Verbosity flags. Switch which function is defined to add or remove
// various output printfs from the source. These are all for debugging
// purposes.
//#define VERBOSE(A) A
#define VERBOSE(A)
//#define DBG(A) A fflush(stdout);
#define DBG(A)
//#define SHOW_RAW(A) A
#define SHOW_RAW(A) 
// There are a lot of DBG statements in the tcp and ip_fragment sections.
// When debugging those areas, it's really nice to know what's going on
// exactly at each point.

// Get the value of the BITth bit from byte offset O bytes from base B.
#define GET_BIT(B,O,BIT) (uint8_t)(((*(B+O)) & (1 << (BIT))) >> BIT )
// Get a two byte little endian u_int at base B and offset O.
#define LE_U_SHORT(B,O) (uint16_t)((B[O]<<8)+B[O+1])
// Get a four byte little endian u_int at base B and offset O.
#define LE_U_INT(B,O) (uint32_t)((B[O]<<24)+(B[O+1]<<16)+(B[O+2]<<8)+B[O+3])
// Get the DNS tcp length prepended field.
#define TCP_DNS_LEN(P,O) ((P[O]<<8) + P[O+1])

// Pre-declarations.
struct tcp_info;
struct ip_fragment;

#define MAX_EXCLUDES 100
// Globals passed in via the command line.
// I don't really want these to be globals, but libpcap doesn't really 
// have the mechanism I need to pass them to the handler.
typedef struct {
    uint16_t EXCLUDED[MAX_EXCLUDES];
    uint16_t EXCLUDES;
    char SEP;
    char * RECORD_SEP;
    int AD_ENABLED;
    int NS_ENABLED;
    int COUNTS;
    int PRETTY_DATE;
    int PRINT_RR_NAME;
    int MISSING_TYPE_WARNINGS;
    char * TCP_STATE_PATH;
    uint32_t DEDUPS;
    struct tcp_info * tcp_sessions_head;
    struct ip_fragment * ip_fragment_head;
    unsigned long long * dedup_hashes;
    uint32_t dedup_pos;
    
} config;

typedef struct dns_question {
    char * name;
    uint16_t type;
    uint16_t cls;
    struct dns_question * next;
} dns_question;

typedef struct dns_rr {
    char * name;
    uint16_t type;
    uint16_t cls;
    const char * rr_name;
    uint16_t ttl;
    uint16_t rdlength;
    uint16_t data_len;
    char * data;
    struct dns_rr * next;
} dns_rr;

typedef struct {
    uint16_t id;
    char qr;
    char AA;
    char TC;
    uint8_t rcode;
    uint8_t opcode;
    uint16_t qdcount;
    dns_question * queries;
    uint16_t ancount;
    dns_rr * answers;
    uint16_t nscount;
    dns_rr * name_servers;
    uint16_t arcount;
    dns_rr * additional;
} dns_info;


#include "tcp.h"
#include "network.h"

uint32_t dns_parse(uint32_t, struct pcap_pkthdr *, uint8_t *, 
                   dns_info *, config *, uint8_t);
void print_summary(ip_info *, transport_info *, dns_info *,
                   struct pcap_pkthdr *, config *);
#endif
