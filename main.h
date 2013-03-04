
#ifndef __DP_MAIN
#define __DP_MAIN

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
#define GET_BIT(B,O,BIT) (unsigned char)(((*(B+O)) & (1 << (BIT))) >> BIT )
// Get a two byte little endian u_int at base B and offset O.
#define LE_U_SHORT(B,O) (u_short)((B[O]<<8)+B[O+1])
// Get a four byte little endian u_int at base B and offset O.
#define LE_U_INT(B,O) (bpf_u_int32)((B[O]<<24)+(B[O+1]<<16)+(B[O+2]<<8)+B[O+3])
// Get the DNS tcp length prepended field.
#define TCP_DNS_LEN(P,O) ((P[O]<<8) + P[O+1])

#define MAX_EXCLUDES 100
// Globals passed in via the command line.
// I don't really want these to be globals, but libpcap doesn't really 
// have the mechanism I need to pass them to the handler.
typedef struct {
    u_short EXCLUDED[MAX_EXCLUDES];
    u_short EXCLUDES;
    char SEP;
    char * RECORD_SEP;
    int AD_ENABLED;
    int NS_ENABLED;
    int PRETTY_DATE;
    int PRINT_RR_NAME;
    int MISSING_TYPE_WARNINGS;
    char * TCP_STATE_PATH;
    bpf_u_int32 DEDUPS;
    tcp_info * tcp_sessions_head;
    ip_fragment * ip_fragment_head;
    unsigned long long * dedup_hashes;
    bpf_u_int32 dedup_pos;
    
} config;

typedef struct dns_question {
    char * name;
    u_short type;
    u_short cls;
    struct dns_question * next;
} dns_question;

typedef struct dns_rr {
    char * name;
    u_short type;
    u_short cls;
    const char * rr_name;
    u_short ttl;
    u_short rdlength;
    u_short data_len;
    char * data;
    struct dns_rr * next;
} dns_rr;

typedef struct {
    u_short id;
    char qr;
    char AA;
    char TC;
    u_char rcode;
    u_char opcode;
    u_short qdcount;
    dns_question * queries;
    u_short ancount;
    dns_rr * answers;
    u_short nscount;
    dns_rr * name_servers;
    u_short arcount;
    dns_rr * additional;
} dns_info;

bpf_u_int32 dns_parse(bpf_u_int32, struct pcap_pkthdr *, u_char *, 
                      dns_info *, config *);
void print_summary(ip_info *, transport_info *, dns_info *,
                   struct pcap_pkthdr *, config *);
#endif
