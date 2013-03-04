#include <arpa/inet.h>
#include <getopt.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "rtypes.h"
#include "types.h"
#include "strutils.h"

// If you want a reasonable place to start walking through the code, 
// go to the 'handler' function at the end.

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

tcp_info * tcp_assemble(tcp_info *);
void tcp_print(tcp_info *);

#define MAX_EXCLUDES 100
#define DEFAULT_TCP_STATE_PATH "/tmp/dnsparse_tcp.state"

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

void tcp_save_state(config *);
tcp_info * tcp_load_state(config *);
ip_fragment * ip_frag_add(ip_fragment *, config *);
void ip_frag_free(config *);
bpf_u_int32 dns_parse(bpf_u_int32, struct pcap_pkthdr *, u_char *, 
                      dns_info *, config *);
void print_summary(ip_info *, transport_info *, dns_info *,
                   struct pcap_pkthdr *, config *);
void handler(u_char *, const struct pcap_pkthdr *, const u_char *);
bpf_u_int32 eth_parse(struct pcap_pkthdr *, u_char *, eth_info *);
bpf_u_int32 mpls_parse(bpf_u_int32, struct pcap_pkthdr *, 
                       u_char *, eth_info *);
bpf_u_int32 ipv4_parse(bpf_u_int32, struct pcap_pkthdr *, 
                       u_char **, ip_info *, config *);
bpf_u_int32 ipv6_parse(bpf_u_int32, struct pcap_pkthdr *,
                       u_char **, ip_info *, config *);
bpf_u_int32 udp_parse(bpf_u_int32, struct pcap_pkthdr *, u_char *, 
                      transport_info *, config *);
void tcp_parse(bpf_u_int32, struct pcap_pkthdr *, u_char *, ip_info *, 
               config *);
void tcp_expire(config *, const struct timeval *);
void dns_rr_free(dns_rr *);
void dns_question_free(dns_question *);
bpf_u_int32 parse_rr(bpf_u_int32, bpf_u_int32, struct pcap_pkthdr *, 
                     u_char *, dns_rr *, config *);
void print_summary(ip_info *, transport_info *, dns_info *,
                   struct pcap_pkthdr *, config *);
void print_rr_section(dns_rr *, char *, config *);
void print_packet(bpf_u_int32, u_char *, bpf_u_int32, bpf_u_int32, u_int);
int dedup(bpf_u_int32, struct pcap_pkthdr *, u_char *,
          ip_info *, transport_info *, config *);

int main(int argc, char **argv) {
    pcap_t * pcap_file;
    char errbuf[PCAP_ERRBUF_SIZE];
    int read;
    config conf;
    
    int c;
    char *cvalue = NULL;
    int print_type_freq = 0;
    int arg_failure = 0;

    const char * OPTIONS = "dfhm:MnurtD:x:s:S";

    // Setting configuration defaults.
    u_char TCP_SAVE_STATE = 1;
    conf.EXCLUDES = 0;
    conf.RECORD_SEP = "";
    conf.SEP = '\t';
    conf.AD_ENABLED = 0;
    conf.NS_ENABLED = 0;
    conf.PRETTY_DATE = 0;
    conf.PRINT_RR_NAME = 0;
    conf.MISSING_TYPE_WARNINGS = 0;
    conf.TCP_STATE_PATH = NULL;
    conf.DEDUPS = 10;
    conf.dedup_pos = 0;

    c = getopt(argc, argv, OPTIONS);
    while (c != -1) {
        switch (c) {
            case 'd':
                conf.AD_ENABLED = 1;
                break;
            case 'f':
                print_parsers();
                return 0;
            case 'm':
                conf.RECORD_SEP = optarg;
                conf.SEP = '\n';
                break;
            case 'M':
                conf.MISSING_TYPE_WARNINGS = 1;
                break;
            case 'n':
                conf.NS_ENABLED = 1;
                break;
            case 'r':
                conf.PRINT_RR_NAME = 1;
                break;
            case 's':
                conf.TCP_STATE_PATH = optarg;
                break;
            case 'S':
                TCP_SAVE_STATE = 0;
                break;
            case 't':
                conf.PRETTY_DATE = 1; 
                break;
            case 'u':
                print_type_freq = 1;
                break;
            case 'D':
                conf.DEDUPS = strtoul(optarg, NULL, 10);
                if (conf.DEDUPS > 10000) {
                    conf.DEDUPS = 10000;
                }
                break;
            case 'x':
                if (conf.EXCLUDES < MAX_EXCLUDES) {
                    int ival = atoi(optarg);
                    if (ival == 0 || ival >= 65536) {
                        fprintf(stderr, "Invalid excluded rtype value. "
                                "Value must be a short int.\n");
                        arg_failure = 1;
                    } else {
                        conf.EXCLUDED[conf.EXCLUDES] = ival;
                        conf.EXCLUDES++; 
                    }
                } else {
                    fprintf(stderr, "Too many excluded rtypes. "
                            "If this limit is an issue, then recompile with "
                            "the MAX_EXCLUDES define set higher.\n");
                    arg_failure = 1;
                }
                break;
            case '?':
                if (optopt == 'x') 
                    fprintf(stderr, "Option -x requires an rtype number.\n");
                else if (optopt == 'm')
                    fprintf(stderr, "Option -m needs a delimiter string.\n");
                else if (isprint(optopt)) 
                    fprintf(stderr, "Unknown option -%c.\n",optopt); 
                else 
                    fprintf(stderr, "Invalid option char: 0x%x.\n", optopt);
            case 'h':
            default:
                arg_failure = 1;
        }
        c = getopt(argc, argv, OPTIONS);
    }

    if (conf.TCP_STATE_PATH == NULL) {
        conf.TCP_STATE_PATH = DEFAULT_TCP_STATE_PATH;
    }

    if (optind == argc - 1) {
        pcap_file = pcap_open_offline(argv[optind], errbuf);
        if (pcap_file == NULL) {
            fprintf(stderr, "Could not open pcapfile.\n%s\n", errbuf);
            return -1;
        }
    } else if (optind >= argc) {
        fprintf(stderr, "No input file specified.\n");
        arg_failure = 1;
    } else {
        fprintf(stderr, "Multiple input files or bad arguments.");
        arg_failure = 1;
    }
    
    if (arg_failure) {
        fprintf(stderr,
        "Usage: dns_parse [-dnthf] [-m<query sep.>] [-x<rtype>] [-s<path>]\n"
        "                 <pcap file>\n"
        "dns_parse parses a pcap file and gives a nicely "
        "formatted ascii string for each dns request.\n"
        "By default the reservation records are tab separated "
        "and the entire record is ended with a newline.\n\n"
        "The comma separated fields printed for each request are:\n"
        "  time - The time of the request relative to the \n"
        "         capture source clock.\n"
        "  srcip, dstip - the source and dest ipv4 addresses.\n"
        "                 ipv6 support is not present.\n"
        "  size - the size of the dns portion of the message.\n"
        "  proto - udp (u) or tcp(t)\n"
        "  query/response - is it a query(q) or response(r)\n"
        "  authoritative - marked with AA if authoritative\n\n"
        "The resource records are printed after these fields, separated by\n"
        "a tab (a newline in multiline mode). \n"
        "By default the resource record format is:\n"
        "<section> <name> <type> <class> <rdata>\n\n"
        "<section> is a symbol denoting record type.\n"
        "    ? - Questions (No rdata is included or printed).\n"
        "    ! - Answers\n"
        "    $ - Name Servers\n"
        "    + - Additional\n"
        "The rdata is parsed by a custom parser that depends on the\n"
        "record type and class. Use the -f option to get a list of\n"
        "the supported record types and documentation on the parsers.\n\n"
        "Args:\n"
        "<pcapfile> - The pcapfile to parse. Use a '-' for stdin\n"
        "-d\n"
        "   Enable the parsing and output of the Additional\n"
        "   Records section. Disabled by default.\n"
        "-D <count>\n"
        "   Keep hashes of the last <count> packets for de-duplication\n"
        "   purposes (max 10,000). A <count> of zero turns off \n"
        "   de-duplication. \n"
        "   Default 10.\n"
        "-f\n"
        "   Print out documentation on the various resource \n"
        "   record parsers.\n"
        "-n\n"
        "   Enable the parsing and output of the Name Server\n"
        "   Records section. Disabled by default.\n"
        "-m<sep> \n"
        "   Multiline mode. Reservation records are newline\n"
        "   separated, and the whole record ends with the\n"
        "   separator given.\n"
        "-M \n"
        "   Print a message for each occurance of a missing class,type\n"
        "   parser.\n"
        "-r \n"
        "   Changes the resource record format to: \n"
        "   <section> <name> <rr_type_name> <rdata>\n"
        "   If the record type isn't known, 'UNKNOWN(<cls>,<type>)' is given\n"
        "   The query record format is the similar, but missing the rdata.\n"
        "-s<path> \n"
        "   Path to the tcp state save file. \n"
        "   This will be loaded (and overwritten) every time dns_parse \n"
        "   is run. \n"
        "   Default is: %s \n"
        "-S \n"
        "   Disable TCP state saving/loading.\n"
        "-t \n"
        "   Print the time/date as in Y/M/D H:M:S format.\n"
        "   The time will be in the local timezone.\n"
        "-u \n"
        "   Print a record of the how many occurances of each class,type\n"
        "   record occurred via stderr when processing completes.\n"
        "-x\n"
        "   Exclude the given reservation record types by \n"
        "   number. This option can be given multiple times.\n",
        DEFAULT_TCP_STATE_PATH);
        return -1;
    }

    conf.ip_fragment_head = NULL;

    // Load and prior TCP session info
    conf.tcp_sessions_head = NULL; 
    if (TCP_SAVE_STATE == 1) {
        tcp_load_state(&conf);
    }

    conf.dedup_hashes = calloc(conf.DEDUPS, sizeof(unsigned long long));
 
    // need to check this for overflow.
    read = pcap_dispatch(pcap_file, -1, (pcap_handler)handler, 
                         (u_char *) &conf);
    
    if (TCP_SAVE_STATE == 1) {
        tcp_save_state(&conf);
    } else {
        tcp_expire(&conf, NULL);
    }

    free(conf.dedup_hashes);
    ip_frag_free(&conf);

    return 0;
}

void handler(u_char * args, const struct pcap_pkthdr *orig_header, 
             const u_char *orig_packet) {
    int pos;
    eth_info eth;
    ip_info ip;
    config * conf = (config *) args;

    // The way we handle IP fragments means we may have to replace
    // the original data and correct the header info, so a const won't work.
    u_char * packet = (u_char *) orig_packet;
    struct pcap_pkthdr header;
    header.ts = orig_header->ts;
    header.caplen = orig_header->caplen;
    header.len = orig_header->len;
    
    VERBOSE(printf("\nPacket %llu.%llu\n", 
                   (unsigned long long)header.ts.tv_sec, 
                   (unsigned long long)header.ts.tv_usec);)
    
    // Parse the ethernet frame. Errors are typically handled in the parser
    // functions. The functions generally return 0 on error.
    pos = eth_parse(&header, packet, &eth);
    if (pos == 0) return;

    // MPLS parsing is simple, but leaves us to guess the next protocol.
    // We make our guess in the MPLS parser, and set the ethtype accordingly.
    if (eth.ethtype == 0x8847) {
        pos = mpls_parse(pos, &header, packet, &eth);
    } 

    // IP v4 and v6 parsing. These may replace the packet byte array with 
    // one from reconstructed packet fragments. Zero is a reasonable return
    // value, so they set the packet pointer to NULL on failure.
    if (eth.ethtype == 0x0800) {
        pos = ipv4_parse(pos, &header, &packet, &ip, conf);
    } else if (eth.ethtype == 0x86DD) {
        pos = ipv6_parse(pos, &header, &packet, &ip, conf);
    } else {
        fprintf(stderr, "Unsupported EtherType: %04x\n", eth.ethtype);
        return;
    }
    if (packet == NULL) return;

    // Transport layer parsing. 
    if (ip.proto == 17) {
        // Parse the udp and this single bit of DNS, and output it.
        dns_info dns;
        transport_info udp;
        pos = udp_parse(pos, &header, packet, &udp, conf);
        if ( pos == 0 ) return;
        // Only do deduplication if DEDUPS > 0.
        if (conf->DEDUPS != 0 ) {
            if (dedup(pos, &header, packet, &ip, &udp, conf) == 1) {
                // A duplicate packet.
                return;
            }
        }
        pos = dns_parse(pos, &header, packet, &dns, conf);
        print_summary(&ip, &udp, &dns, &header, conf);
    } else if (ip.proto == 6) {
        // Hand the tcp packet over for later reconstruction.
        tcp_parse(pos, &header, packet, &ip, conf); 
    } else {
        fprintf(stderr, "Unsupported Transport Protocol(%d)\n", ip.proto);
        return;
    }
   
    // Expire tcp sessions, and output them if possible.
    DBG(printf("Expiring TCP.\n");)
    tcp_expire(conf, &header.ts);
}

bpf_u_int32 eth_parse(struct pcap_pkthdr *header, u_char *packet,
                      eth_info * eth) {
    bpf_u_int32 pos = 0;

    int i;

    if (header->len < 14) {
        fprintf(stderr, "Truncated Packet(eth)\n");
        return 0;
    }

    while (pos < 6) {
        eth->dstmac[pos] = packet[pos];
        eth->srcmac[pos] = packet[pos+6];
        pos++;
    }
    pos = pos + 6;

    // Skip VLAN tagging 
    if (packet[pos] == 0x81 && packet[pos+1] == 0) pos = pos + 4;
    
    eth->ethtype = (packet[pos] << 8) + packet[pos+1];
    pos = pos + 2;

    SHOW_RAW(
        printf("\neth ");
        print_packet(header->len, packet, 0, pos, 18);
    )
    VERBOSE(
        printf("dstmac: %02x:%02x:%02x:%02x:%02x:%02x, "
               "srcmac: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->dstmac[0],eth->dstmac[1],eth->dstmac[2],
               eth->dstmac[3],eth->dstmac[4],eth->dstmac[5],
               eth->srcmac[0],eth->srcmac[1],eth->srcmac[2],
               eth->srcmac[3],eth->srcmac[4],eth->srcmac[5]);
    )
    return pos;
}

// Parse MPLS. We don't care about the data in these headers, all we have
// to do is continue parsing them until the 'bottom of stack' flag is set.
bpf_u_int32 mpls_parse(bpf_u_int32 pos, struct pcap_pkthdr *header,
                       u_char *packet, eth_info * eth) {
    // Bottom of stack flag.
    u_char bos;
    do {
        VERBOSE(printf("MPLS Layer.\n");)
        // Deal with truncated MPLS.
        if (header->len < (pos + 4)) {
            fprintf(stderr, "Truncated Packet(mpls)\n");
            return 0;
        }
        
        bos = packet[pos + 2] & 0x01;
        pos += 4;
        DBG(printf("MPLS layer. \n");)
    } while (bos == 0);

    if (header->len < pos) {
        fprintf(stderr, "Truncated Packet(post mpls)\n");
        return 0;
    }


    // 'Guess' the next protocol. This can result in false positives, but
    // generally not.
    u_char ip_ver = packet[pos] >> 4;
    switch (ip_ver) {
        case IPv4:
            eth->ethtype = 0x0800; break;
        case IPv6:
            eth->ethtype = 0x86DD; break;
        default:
            eth->ethtype = 0;
    }

    return pos;
}

bpf_u_int32 ipv4_parse(bpf_u_int32 pos, struct pcap_pkthdr *header, 
                       u_char ** p_packet, ip_info * ip, config * conf) {

    bpf_u_int32 h_len;
    int i;
    ip_fragment * frag = NULL;
    u_char frag_mf;
    u_short frag_offset;
    
    // For convenience and code consistency, dereference the packet **.
    u_char * packet = *p_packet;

    if (header-> len - pos < 20) {
        fprintf(stderr, "Truncated Packet(ipv4)\n");
        p_packet = NULL;
        return 0;
    }
   
    h_len = packet[pos] & 0x0f;
    ip->length = (packet[pos+2] << 8) + packet[pos+3] - h_len*4;
    ip->proto = packet[pos+9];

    IPv4_MOVE(ip->src, packet + pos + 12);
    IPv4_MOVE(ip->dst, packet + pos + 16);

    // Set if NOT the last fragment.
    frag_mf = (packet[pos+6] & 0x20) >> 5;
    // Offset for this data in the fragment.
    frag_offset = ((packet[pos+6] & 0x1f) << 11) + (packet[pos+7] << 3);
    
    SHOW_RAW(
        printf("\nipv4\n");
        print_packet(header->len, packet, pos, pos + 4*h_len, 4);
    )
    VERBOSE(
        printf("version: %d, length: %d, proto: %d\n", 
                IPv4, ip->length, ip->proto);
        printf("src ip: %s, ", iptostr(&ip->src));
        printf("dst ip: %s\n", iptostr(&ip->dst));
    )

    if (frag_mf == 1 || frag_offset != 0) {
        VERBOSE(printf("Fragmented IPv4, offset: %u, mf:%u\n", frag_offset,
                                                               frag_mf);)
        frag = malloc(sizeof(ip_fragment));
        frag->start = frag_offset;
        // We don't try to deal with endianness here, since it 
        // won't matter as long as we're consistent.
        frag->islast = !frag_mf;
        frag->id = *((u_short *)(packet + pos + 4));
        frag->src = ip->src;
        frag->dst = ip->dst;
        frag->end = frag->start + ip->length;
        frag->data = malloc(sizeof(u_char) * ip->length);
        frag->next = frag->child = NULL;
        memcpy(frag->data, packet + pos + 4*h_len, ip->length);
        // Add the fragment to the list.
        // If this completed the packet, it is returned.
        frag = ip_frag_add(frag, conf); 
        if (frag != NULL) {
            // Update the IP info on the reassembled data.
            header->len = ip->length = frag->end - frag->start;
            p_packet = &(frag->data);
            free(frag);
            return 0;
        }
        // Signals that there is no more work to do on this packet.
        p_packet = NULL;
        return 0;
    } 

    // move the position up past the options section.
    return pos + 4*h_len;

}

bpf_u_int32 ipv6_parse(bpf_u_int32 pos, struct pcap_pkthdr *header,
                       u_char ** p_packet, ip_info * ip, config * conf) {

    // For convenience and code consistency, dereference the packet **.
    u_char * packet = *p_packet;

    // In case the IP packet is a fragment.
    ip_fragment * frag = NULL;
    bpf_u_int32 header_len = 0;

    if (header->len < (pos + 40)) {
        fprintf(stderr, "Truncated Packet(ipv6)\n");
        p_packet=NULL; return 0;
    }
    ip->length = (packet[pos+4] << 8) + packet[pos+5];
    IPv6_MOVE(ip->src, packet + pos + 8);
    IPv6_MOVE(ip->dst, packet + pos + 24);

    // Jumbo grams will have a length of zero. We'll choose to ignore those,
    // and any other zero length packets.
    if (ip->length == 0) {
        fprintf(stderr, "Zero Length IP packet, possible Jumbo Payload.\n");
        p_packet=NULL; return 0;
    }

    u_char next_hdr = packet[pos+6];
    VERBOSE(print_packet(header->len, packet, pos, pos+40, 4);)
    VERBOSE(printf("IPv6 src: %s, ", iptostr(&ip->src));)
    VERBOSE(printf("IPv6 dst: %s\n", iptostr(&ip->dst));)
    pos += 40;
   
    // We pretty much have no choice but to parse all extended sections,
    // since there is nothing to tell where the actual data is.
    u_char done = 0;
    while (done == 0) {
        VERBOSE(printf("IPv6, next header: %u\n", next_hdr);)
        switch (next_hdr) {
            // Handle hop-by-hop, dest, and routing options.
            // Yay for consistent layouts.
            case IPPROTO_HOPOPTS:
            case IPPROTO_DSTOPTS:
            case IPPROTO_ROUTING:
                if (header->len < (pos + 40)) {
                    fprintf(stderr, "Truncated Packet(ipv6)\n");
                    p_packet = NULL; return 0;
                }
                next_hdr = packet[pos];
                // The headers are 16 bytes longer.
                header_len += 16;
                pos += packet[pos+1] + 1;
                break;
            case 51: // Authentication Header. See RFC4302
                if (header->len < (pos + 2)) {
                    fprintf(stderr, "Truncated Packet(ipv6)\n");
                    p_packet = NULL; return 0;
                } 
                next_hdr = packet[pos];
                header_len += (packet[pos+1] + 2) * 4;
                pos += (packet[pos+1] + 2) * 4;
                if (header->len < pos) {
                    fprintf(stderr, "Truncated Packet(ipv6)\n");
                    p_packet = NULL; return 0;
                } 
                break;
            case 50: // ESP Protocol. See RFC4303.
                // We don't support ESP.
                fprintf(stderr, "Unsupported protocol: IPv6 ESP.\n");
                if (frag != NULL) free(frag);
                p_packet = NULL; return 0;
            case 135: // IPv6 Mobility See RFC 6275
                if (header->len < (pos + 2)) {
                    fprintf(stderr, "Truncated Packet(ipv6)\n");
                    p_packet = NULL; return 0;
                }  
                next_hdr = packet[pos];
                header_len += packet[pos+1] * 8;
                pos += packet[pos+1] * 8;
                if (header->len < pos) {
                    fprintf(stderr, "Truncated Packet(ipv6)\n");
                    p_packet = NULL; return 0;
                } 
                break;
            case IPPROTO_FRAGMENT:
                // IP fragment.
                next_hdr = packet[pos];
                frag = malloc(sizeof(ip_fragment));
                frag->start = (packet[pos+2] << 8) + (packet[pos+3] & 0xf4);
                frag->islast = packet[pos+3] & 0x01;
                // We don't try to deal with endianness here, since it 
                // won't matter as long as we're consistent.
                frag->id = *(bpf_u_int32 *)(packet+pos+4);
                // The headers are 8 bytes longer.
                header_len += 8;
                pos += 8;
                break;
            default:
                // All non ipv6 extension protocols
                done = 1;
        }
    }

    ip->proto = next_hdr;
    ip->length = ip->length - header_len;
    
    // Handle fragments.
    if (frag != NULL) {
        frag->src = ip->src;
        frag->dst = ip->dst;
        frag->end = frag->start + ip->length;
        frag->next = frag->child = NULL;
        frag->data = malloc(sizeof(u_char) * ip->length);
        VERBOSE(printf("IPv6 fragment. offset: %d, m:%u\n", frag->start,
                                                            frag->islast);)
        memcpy(frag->data, packet+pos, ip->length);
        // Add the fragment to the list.
        // If this completed the packet, it is returned.
        frag = ip_frag_add(frag, conf); 
        if (frag != NULL) {
            ip->length = frag->end - frag->start;
            p_packet = &(frag->data);
            free(frag);
            return 0;
        }
        // Signals that there is no more work to do on this packet.
        p_packet = NULL;
        return 0;
    } else {
        return pos;
    }

}

// Parse the udp headers.
bpf_u_int32 udp_parse(bpf_u_int32 pos, struct pcap_pkthdr *header, 
                      u_char *packet, transport_info * udp, 
                      config * conf) {
    u_short test;
    if (header->len - pos < 8) {
        fprintf(stderr, "Truncated Packet(udp)\n");
        return 0;
    }

    udp->srcport = (packet[pos] << 8) + packet[pos+1];
    udp->dstport = (packet[pos+2] << 8) + packet[pos+3];
    udp->length = (packet[pos+4] << 8) + packet[pos+5];
    udp->transport = UDP;
    VERBOSE(printf("udp\n");)
    VERBOSE(printf("srcport: %d, dstport: %d, len: %d\n", udp->srcport, udp->dstport, udp->length);)
    SHOW_RAW(print_packet(header->len, packet, pos, pos, 4);)
    return pos + 8;
}

// Parse and output a packet's DNS data.
void print_summary(ip_info * ip, transport_info * trns, dns_info * dns,
                   struct pcap_pkthdr * header, config * conf) {
    char date[200];
    char proto;

    bpf_u_int32 dnslength;
    dns_rr *next;
    dns_question *qnext;

    // Print the time stamp.
    if (conf->PRETTY_DATE) {
        struct tm *time;
        size_t result;
        const char * format = "%D %T";
        time = localtime(&(header->ts.tv_sec));
        result = strftime(date, 200, format, time);
        if (result == 0) strncpy(date, "Date format error", 20);
    } else 
        sprintf(date, "%d.%06d", (int)header->ts.tv_sec, 
                                 (int)header->ts.tv_usec);
   
    // Print the transport protocol indicator.
    if (ip->proto == 17) {
        proto = 'u';
    } else if (ip->proto == 6) {
        proto = 't';
    }
    fflush(stdout);
    dnslength = trns->length;

    // Print the IP addresses and the basic query information.
    printf("%s,%s,", date, iptostr(&ip->src));
    printf("%s,%d,%c,%c,%s", iptostr(&ip->dst),
           dnslength, proto, dns->qr ? 'r':'q', dns->AA?"AA":"NA");

    // Go through the list of queries, and print each one.
    qnext = dns->queries;
    while (qnext != NULL) {
        printf("%c? ", conf->SEP);
        if (conf->PRINT_RR_NAME) {
            rr_parser_container * parser; 
            parser = find_parser(qnext->cls, qnext->type);
            if (parser->name == NULL) 
                printf("%s UNKNOWN(%s,%d)", qnext->name, parser->name, 
                                            qnext->type, qnext->cls);
            else 
                printf("%s %s", qnext->name, parser->name);
        } else
            printf("%s %d %d", qnext->name, qnext->type, qnext->cls);
        qnext = qnext->next; 
    }

    // Print it resource record type in turn (for those enabled).
    print_rr_section(dns->answers, "!", conf);
    if (conf->NS_ENABLED) 
        print_rr_section(dns->name_servers, "$", conf);
    if (conf->AD_ENABLED) 
        print_rr_section(dns->additional, "+", conf);
    printf("%c%s\n", conf->SEP, conf->RECORD_SEP);
    
    dns_question_free(dns->queries);
    dns_rr_free(dns->answers);
    dns_rr_free(dns->name_servers);
    dns_rr_free(dns->additional);
    fflush(stdout); fflush(stderr);
}

void print_packet(bpf_u_int32 max_len, u_char *packet,
                  bpf_u_int32 start, bpf_u_int32 end, u_int wrap) {
    int i=0;
    while (i < end - start && (i + start) < max_len) {
        printf("%02x ", packet[i+start]);
        i++;
        if ( i % wrap == 0) printf("\n");
    }
    if ( i % wrap != 0) printf("\n");
    return;
}

void dns_rr_free(dns_rr * rr) {
    if (rr == NULL) return;
    if (rr->name != NULL) free(rr->name);
    if (rr->data != NULL) free(rr->data);
    dns_rr_free(rr->next);
    free(rr);
}

void dns_question_free(dns_question * question) {
    if (question == NULL) return;
    if (question->name != NULL) free(question->name);
    dns_question_free(question->next);
    free(question);
}

// Add this ip fragment to the our list of fragments. If we complete
// a fragmented packet, return it. 
// Limitations - Duplicate packets may end up in the list of fragments.
//             - We aren't going to expire fragments, and we aren't going
//                to save/load them like with TCP streams either. This may
//                mean lost data.
ip_fragment * ip_frag_add(ip_fragment * this, config * conf) {
    ip_fragment ** curr = &(conf->ip_fragment_head);
    ip_fragment ** found = NULL;
 
    DBG(printf("Adding fragment at %p\n", this);)

    // Find the matching fragment list.
    while (*curr != NULL) {
        if ((*curr)->id == this->id && 
            IP_CMP((*curr)->src, this->src) &&
            IP_CMP((*curr)->dst, this->dst)) {
            found = curr;
            DBG(printf("Match found. %p\n", *found);)
            break;
        }
        curr = &(*curr)->next;
    }
    
    // At this point curr will be the head of our matched chain of fragments, 
    // and found will be the same. We'll use found as our pointer into this
    // chain, and curr to remember where it starts.
    if (found == NULL) {
        found = curr;
    }

    // If there wasn't a matching list, then we're done.
    if (*found == NULL) {
        DBG(printf("No matching fragments.\n");)
        this->next = conf->ip_fragment_head;
        conf->ip_fragment_head = this;
        return NULL;
    }

    while (*found != NULL) {
        DBG(printf("*found: %u-%u, this: %u-%u\n",
                   (*found)->start, (*found)->end,
                   this->start, this->end);)
        if ((*found)->start >= this->end) {
            DBG(printf("It goes in front of %p\n", *found);)
            // It goes before, so put it there.
            this->child = *found;
            this->next = (*found)->next;
            *found = this;
            break;
        } else if ((*found)->child == NULL && 
                    (*found)->end <= this->start) {
            DBG(printf("It goes at the end. %p\n", *found);)
           // We've reached the end of the line, and that's where it
            // goes, so put it there.
            (*found)->child = this;
            break;
        }
        DBG(printf("What: %p\n", *found);)
        found = &((*found)->next);
    }
    DBG(printf("What: %p\n", *found);)

    // We found no place for the fragment, which means it's a duplicate
    // (or the chain is screwed up...)
    if (*found == NULL) {
        DBG(printf("No place for fragment: %p\n", *found);)
        free(this);
        return NULL;
    }

    // Now we try to collapse the list.
    found = curr;
    while ((*found != NULL) && (*found)->child != NULL) {
        ip_fragment * child = (*found)->child;
        if ((*found)->end == child->start) {
            DBG(printf("Merging frag at offset %u-%u with %u-%u\n", 
                        (*found)->start, (*found)->end,
                        child->start, child->end);)
            bpf_u_int32 child_len = child->end - child->start;
            bpf_u_int32 fnd_len = (*found)->end - (*found)->start;
            u_char * buff = malloc(sizeof(u_char) * (fnd_len + child_len));
            memcpy(buff, (*found)->data, fnd_len);
            memcpy(buff + fnd_len, child->data, child_len);
            (*found)->end = (*found)->end + child_len;
            (*found)->islast = child->islast;
            (*found)->child = child->child;
            free(child->data);
            free(child);
        } else {
            found = &(*found)->child;
        }
    }

    DBG(printf("*curr, start: %u, end: %u, islast: %u\n", 
                (*curr)->start, (*curr)->end, (*curr)->islast);)
    // Check to see if we completely collapsed it.
    // *curr is the pointer to the first fragment.
    if ((*curr)->islast != 0) {
        ip_fragment * ret = *curr;
        // Remove this from the fragment list.
        *curr = (*curr)->next;
        DBG(printf("Returning reassembled fragments.\n");)
        return ret;
    }
    // This is what happens when we don't complete a packet.
    return NULL;
}

// Free the lists of IP fragments.
void ip_frag_free(config * conf) {
    ip_fragment * curr;
    ip_fragment * child;
    
    while (conf->ip_fragment_head != NULL) {
        curr = conf->ip_fragment_head;
        conf->ip_fragment_head = curr->next;
        while (curr != NULL) {
            child = curr->child;
            free(curr->data);
            free(curr);
            curr = child;
        }
    }
}

u_short tcp_checksum(ip_info *ip, u_char *packet, 
                     bpf_u_int32 pos, struct pcap_pkthdr *header) {
    unsigned int sum = 0;
    unsigned int i;

    if (ip->src.vers == IPv4) {
        bpf_u_int32 srcip = ip->src.addr.v4.s_addr; 
        bpf_u_int32 dstip = ip->dst.addr.v4.s_addr; 
      
        // Put together the psuedo-header preamble for the checksum calculation.
        // I handle the IP's in a rather odd manner and save a few cycles.
        // Instead of arranging things such that for ip d.c.b.a -> cd + ab
        //   I do cb + ad, which is equivalent. 
        sum += (srcip >> 24) + ((srcip & 0xff) << 8);
        sum += (srcip >> 8) & 0xffff;
        sum += (dstip >> 24) + ((dstip & 0xff) << 8);
        sum += (dstip >> 8) & 0xffff;
        sum += ip->proto;
        sum += ip->length;
    } else {
        u_short * src_v6 = ip->src.addr.v6.s6_addr16;
        u_short * dst_v6 = ip->dst.addr.v6.s6_addr16;
        for (i=0; i<8; i++) {
            sum += (src_v6[i] >> 8) + ((src_v6[i] & 0xff) << 8);
            sum += (dst_v6[i] >> 8) + ((dst_v6[i] & 0xff) << 8);
        }
        sum += ip->length;
        sum += TCP;
    }
      
    // Add the TCP Header up to the checksum, which we'll skip.
    for (i=0; i < 16; i += 2) {
        sum += LE_U_SHORT(packet, pos + i);
    }
    
    // Skip the checksum.
    pos = pos + i + 2;
    
    // Add the rest of the packet, stopping short of a final odd byte.
    while (pos < header->len - 1) {
        sum += LE_U_SHORT(packet, pos);
        pos += 2;
    }
    // Pad the last, odd byte if present.
    if (pos < header->len) 
        sum += packet[pos] << 8;

    // All the overflow bits should be added to the lower 16, including the
    // overflow from adding the overflow.
    while (sum > 0xffff) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // Take the one's compliment (logical not) and we're done.
    return ~sum;
}

// The one-half second expiration time is chosen simply because it's the 
// shortest time that consistently works. Shorter and you may miss some
// late arriving packets (.1 seconds misses quite a few). Longer and
// it's more likely that continuous sessions will never expire.
#define TCP_EXPIRE_USECS 500000
#define __USEC_RES 1000000
#define is_expired(now, old) (\
    ((long long) (now).tv_sec*__USEC_RES + (now).tv_usec) - \
    ((long long) (old).tv_sec*__USEC_RES + (old).tv_usec)) > \
      TCP_EXPIRE_USECS

// Parse the tcp data, and put it in our lists to be reassembled later.
void tcp_parse(bpf_u_int32 pos, struct pcap_pkthdr *header, 
               u_char *packet, ip_info *ip, config * conf) {
    // This packet.
    tcp_info * tcp;
    // For traversing the session list.
    tcp_info ** next;
    // Will hold the matching session when we look.
    tcp_info * sess = NULL;
    int i;
    unsigned int offset;
    bpf_u_int32 data_len;
    u_short checksum;
    u_short actual_checksum;
   
    tcp = malloc(sizeof(tcp_info));

    tcp->next_sess = NULL;
    tcp->next_pkt = NULL;
    tcp->prev_pkt = NULL;
    tcp->ts = header->ts;
    tcp->src = ip->src;
    tcp->dst = ip->dst;
    tcp->srcport = LE_U_SHORT(packet, pos);
    tcp->dstport = LE_U_SHORT(packet, pos+2);
    tcp->sequence = LE_U_INT(packet, pos + 4);
    tcp->ack_num = LE_U_INT(packet, pos + 8);
    tcp->ack = GET_BIT(packet, pos + 13, 5);
    tcp->syn = GET_BIT(packet, pos + 13, 1);
    tcp->fin = GET_BIT(packet, pos + 13, 0);
    tcp->rst = GET_BIT(packet, pos + 13, 2);
    offset = packet[pos + 12] >> 4;

    if ((pos + offset*4) > header->len) {
        fprintf(stderr, "Truncated TCP packet: %d, %d\n", offset, header->len);
        free(tcp);
        return;
    }
    tcp->len = ip->length - offset*4;
  
    // Ignore packets with a bad checksum
    checksum = LE_U_SHORT(packet, pos + 16);

    actual_checksum = tcp_checksum(ip, packet, pos, header);
    if (checksum != actual_checksum || 
        // 0xffff and 0x0000 are both equal to zero in one's compliment,
        // so these are actually the same.
        (checksum == 0xffff && actual_checksum == 0x0000) ||
        (checksum == 0x0000 && actual_checksum == 0xffff) ) {
        // Do Bad Checksum stuff
        DBG(printf("Bad checksum.");)
        free(tcp);
        return;
    } else if (checksum == 0x0000 && tcp->rst) {
        // Ignore, since it's a reset packet.
    }
    
    if (tcp->len > 0) {
        tcp->data = malloc(sizeof(char) * (tcp->len));
        memcpy(tcp->data, packet + pos + (offset*4), tcp->len);
    } else
        tcp->data = NULL;

    DBG(printf("This pkt - %p: ", tcp);)
    DBG(tcp_print(tcp);)
    DBG(printf("The head - %p: ", conf->tcp_sessions_head);)
    DBG(tcp_print(conf->tcp_sessions_head);)

    DBG(printf("Finding the matching session.\n");)
    // Keep in mind 'next' is a pointer to the pointer to the next item.
    // Find a matching session, if we have one. 
    // We treat sessions as 1-way communications. The other direction
    // is handled completely separately.
    next = &(conf->tcp_sessions_head);
    while (*next != NULL) {
        DBG(printf("Checking: ");)
        DBG(tcp_print(*next);)
        if ( IP_CMP((*next)->src, tcp->src) &&
             IP_CMP((*next)->dst, tcp->dst) && 
             (*next)->srcport == tcp->srcport &&
             (*next)->dstport == tcp->dstport) {
            
            DBG(printf("Match found:\n  ");)
            DBG(tcp_print(*next);)
           
            // This is the matching session.
            sess = *next;

            // Assign this to the packet chain.
            sess->next_pkt = tcp;
            tcp->prev_pkt = sess;
            // Since this will be the head, it needs to know where 
            // the next session is.
            tcp->next_sess = sess->next_sess;
            // The current packet is now the head packet of this session.
            sess = tcp;

            // The pointer to the next object should now be set to skip one.
            *next = sess->next_sess;
            // Set sess's next pointer to the old head.
            sess->next_sess = conf->tcp_sessions_head;
            // Then stick our sess back in as the head of the list.
            conf->tcp_sessions_head = sess;
            // We found our session, we're done.
            break;
        } 
        next = &(*next)->next_sess;
    }

    // No matching session found.
    if (sess == NULL) {
        DBG(printf("No match found.\n");)
        tcp->next_sess = conf->tcp_sessions_head;
        conf->tcp_sessions_head = tcp; 
    }

    tcp_info * c_next = conf->tcp_sessions_head;
    bpf_u_int32 sess_total = 0;
    while (c_next != NULL) {
        DBG(printf("Sessions[%d] - %p: ", sess_total, c_next);)
        DBG(tcp_print(c_next);)
        sess_total++;
        c_next = c_next->next_sess;
    }
    DBG(printf("Current sessions in chain: %d\n", sess_total);)

    return;
}

// Go through the list of tcp sessions and expire any old ones.
// (Old is defined by TCP_EXPIRE_USECS).
// The expired sessions are reassembled (or at least an attempt is made).
// The reassembled data is handed of the the dns parser, and we
// output the results.
// Now should be the timeval that came with the most recent packet.
// Now can also be NULL, which will expire everything.
void tcp_expire(config * conf, const struct timeval * now ) {
    tcp_info * head = NULL;
    tcp_info ** ptr = &head;
    tcp_info ** next = &(conf->tcp_sessions_head);

    while (*next != NULL) {
        // Check to see if this session is expired based on the time given.
        if (now == NULL || is_expired(*now, (*next)->ts)) {
            // We need this because we'll probably end up free the 
            // first packet of the session.
            tcp_info * next_sess = (*next)->next_sess;
            // Add this session to the list of of returned sessions
            
            *ptr = tcp_assemble(*next);
            // *next is probably freed now, unless it was returned as *ptr.
             
            // Remove this session from the main session list.
            *next = next_sess;

            // If the assembled stream was empty, skip to the next one.
            DBG(printf("*ptr %p\n", *ptr);)
            if (*ptr == NULL) {
                continue;
            }
            
            // Set ptr to point to the where the next expired session
            // should be added to the list.
            ptr = &(*ptr)->next_sess;
            // Clear that pointer.
            *ptr = NULL;
        } else {
            // Skip this session, it isn't expired.
            next = &(*next)->next_sess;
        }
        
    }
   
    // Step through all the assembled sessions, dns parse the data, and
    // output it.
    //
    // The madness you're about to experience stems from the fact that a 
    // session may contain multiple DNS requests. Additionally, we might
    // just have junk, and need a rough way of telling the difference.
    // With TCP DNS, the DNS data is prepended with a two byte length,
    // so we at least know how long it is. 
    while (head != NULL) {
        bpf_u_int32 size = (head->data[0] << 8) + head->data[1];
        
        // There is a possiblity that this session won't start at the
        // the beginning of the data; that we've caught a session mid-stream.
        // Assuming we have expired it at a reasonable end, we can use the 
        // length bytes to test our start position. If our length bytes allow
        // us to correctly jump the length of the packet, then we're good.
        // (Probably)
        unsigned long long offset;
        unsigned long long dns_len;
        char offset_found = 0;
        for (offset=0; offset < head->len-1; offset++) {
            unsigned long long pos = offset;
            while (pos + 1 < head->len) {
                dns_len = TCP_DNS_LEN(head->data, pos);
                // We shouldn't ever have an offset of 0.
                if (dns_len == 0) break;
                pos += 2 + dns_len;
            }
            // We've found the right offset (probably 0).
            if (pos == head->len) {
                offset_found = 1;
                break;
            }
        }
        
        // If we couldn't find the right offset, just try an offset of 
        // zero as long as that offset isn't longer than all of our data.
        if (offset_found == 0) {
            if   (head->len > 2 && 
                  TCP_DNS_LEN(head->data, 0) < head->len &&
                  TCP_DNS_LEN(head->data, 0) > 12 ) {
                offset = 0;
            } else { 
                char * bad_data = escape_data(head->data, 0, head->len);
                printf("Bad TCP stream: %s\n", bad_data);
                free(bad_data);
            }
        }

        // Go through the stream offset by offset, create a fake packet
        // header (and packet data), and hand both off to the DNS parser.
        // The results are output.
        if (offset + 1 < head->len) {
            dns_len = TCP_DNS_LEN(head->data, offset);
        } else {
            // Skip trying to parse this.
            dns_len = head->len;
        }
        while (offset + dns_len < head->len) {
            dns_info dns;
            ip_info ip;
            transport_info trns;
            struct pcap_pkthdr header;
            bpf_u_int32 pos;

            header.ts = head->ts;
            header.caplen = head->len;
            header.len = head->len;
            trns.srcport = head->srcport;
            trns.dstport = head->dstport;
            trns.length = head->len;
            trns.transport = TCP;
            ip.src = head->src;
            ip.dst = head->dst;
            ip.proto = 0x06;
            DBG(printf("Parsing DNS (TCP).\n");)
            pos = dns_parse(offset + 2, &header, head->data, &dns, conf);
            if (pos != 0) {
                print_summary(&ip, &trns, &dns, &header, conf);
            }
           
            if (pos != offset + 2 + dns_len) {
                // If these don't match up, then there is no point in
                // continuing for this session.
                fprintf(stderr, "Mismatched TCP lengths: %u, %u.\n",
                        pos, (offset + 2 + dns_len));
                break;
            }
            offset += 2 + dns_len;
            if (offset + 1 < head->len) {
                // We don't want to try to parse the length if we're past
                // the end of the packet.
                dns_len = TCP_DNS_LEN(head->data, offset);
            }
        }

        tcp_info * tmp;
        tmp = head;
        head = head->next_sess;
        free(tmp->data);
        free(tmp);
    }
}

// Go through the tcp starting at 'base'. Hopefully it will all be there.
// Otherwise assemble as much as you can. 
// In doing this all child packets are freed (and their data chunks), 
// and a allocation is made. This is attached to the 'base' tcp_info object.
// That tcp_info object has all its point sess and packet pointers set to
// NULL.
// It is assumed that the total data portion will fit in memory (twice actually,
// since the original allocations will be freed after assembly is complete).
tcp_info * tcp_assemble(tcp_info * base) {
    tcp_info **curr;
    tcp_info *origin = NULL;
    bpf_u_int32 curr_seq;
    // We'll keep track of the total size of data to copy.
    long long total_length = 0;
    // Where we are in the copying.
    long long pos = 0;
    // The actual data pointer for the final data.
    u_char * final_data;

    // All the pieces of data to reassemble.
    char ** data_chain;
    // The sizes of each piece.
    bpf_u_int32 * data_lengths;
    size_t dc_i = 0;
    bpf_u_int32 i;
    
    DBG(printf("In TCP_assembly.\n");)
    DBG(printf("Assembling:\n");)
    DBG(tcp_print(base);)

    // Figure out the max length of the data chain.
    // Move base along to be the oldest packet, so we can work on this
    // from the start rather than the end.
    for (curr=&base; *curr != NULL; curr = &(*curr)->prev_pkt) {
        dc_i++;
        base = *curr;
    }
    DBG(printf("Making the data_chain vars.\n");)
    data_chain = malloc(sizeof(char *) * dc_i);
    data_lengths = malloc(sizeof(bpf_u_int32) * dc_i);
    for (i=0; i<dc_i; i++) {
        data_chain[i] = NULL;
        data_lengths[i] = 0;
    }

    // Find the first syn packet
    curr = &base;
    while (*curr != NULL) {
        DBG(tcp_print(*curr);)
        if ((*curr)->syn) {
            // Make note of this packet, it's the object we'll return.
            origin = *curr;
            curr_seq = (*curr)->sequence;
            DBG(printf("Found first sequence #: %x\n", curr_seq);)
            break;
        }
        curr = &(*curr)->next_pkt;
    }
    
    if (origin == NULL) {
        // If we fail to find the syn packet, use the earliest packet.
        // This means we might jump in in the middle of a session, but
        // we may still be able to pull out some DNS data if we're lucky.
        origin = base;
        curr_seq = base->sequence;
    }

    // Gather all the bits of data, in order. 
    // The chain is destroyed bit by bit, except for the last tcp object.
    // The packets should be in order, or close to it, making this approx. 
    // O(n). In the random order case, it's O(n^2).
    // Skip all this if the origin is NULL, since we don't have a starting
    // point anyway.
    dc_i = 0;
    while (base != NULL && origin != NULL) {
        // Search for the packet with the next sequence number that has 
        // non-zero length.
        tcp_info ** next_best = NULL;
        for (curr = &base; *curr != NULL; curr = &(*curr)->next_pkt) {
            if ((*curr)->sequence == curr_seq) {
                if ((*curr)->len > 0) {
                    // We found a packet at that sequence with data, it 
                    // should be what we want.
                    break;
                } else if (next_best == NULL) {
                    // A zero length packet will do if we can't find anything
                    // better.
                    next_best = curr;
                }
            }
        }
        // If we didn't find a matching packet with data, use the least
        // recent zero length packet. If that should be the origin, but 
        // isn't, adjust the origin packet.
        if (*curr == NULL && next_best != NULL) {
            if (*next_best != NULL) {
                curr = next_best;
            }
        }
        
        // Set the origin to this packet if they have the same sequence.
        // Guarantees that the origin will be a packet removed from the
        // packet list (and thus not thrown away later).
        // This will only occur for the first sequence number.
        if (*curr != NULL && (origin->sequence == (*curr)->sequence)) {
            origin = *curr;
        }
 
        if (*curr != NULL) {
            DBG(printf("Current assembly packet: ");)
            DBG(tcp_print(*curr);)
            tcp_info * tmp;
            //DBG(print_packet((*curr)->len, (*curr)->data, 0, (*curr)->len, 8);)
            // We found a match.
            // Save the data and it's length.
            data_chain[dc_i] = (*curr)->data;
            data_lengths[dc_i] = (*curr)->len;
            total_length += (*curr)->len;
            dc_i++;
            
            // Look for the next sequence number.
            DBG(printf("curr_seq, seq: %x, %x\n", curr_seq, (*curr)->sequence);)
            if ((*curr)->len == 0) {
                curr_seq++;
            } else {
                curr_seq += (*curr)->len;
            }
            
            // Remove this packet from the list.
            tmp = *curr;
            *curr = (*curr)->next_pkt;
            // Free that packet object as long as it isn't the origin.
            if (tmp != origin) {
                // The data part will be freed separately in a bit.
                DBG(printf("Freeing: %p\n", tmp);)
                free(tmp);
            }

        } else {
            // We didn't find a match. We're probably done now.
            break;
        }
        // Start over from the beginning of the list every time.
        curr = &base;
    }

    // Free any remaining packet objects and their data.
    while (base != NULL) {
        tcp_info * next = base->next_pkt;
        DBG(printf("Free unused packet:\n");)
        DBG(tcp_print(base);)
        free(base->data);
        free(base);
        base = next;
    }

    DBG(printf("Total_length: %lld\n", total_length);)

    // Make the final data struct.
    //XXX This could be seriously freaking huge. We'll ignore that for now.
    //XXX It should be fine, in theory, thanks to virtual memory and big disks,
    //XXX but it's good this is only DNS data, right?
    // Combine the data.
    // We'll skip combining the data, and just free the chain, if there 
    // isn't any data to deal with.
    if (total_length > 0) {
        final_data = malloc(sizeof(u_char) * total_length);
        for(i=0; i < dc_i; i++) {
            if (data_chain[i] != NULL) { 
                memcpy(final_data + pos, data_chain[i], data_lengths[i]);
                pos += data_lengths[i];
                DBG(printf("data_chain[%d] free: ", i);)
                free(data_chain[i]);
            }
        }
    }

    DBG(printf("data_chain, lengths, free.\n");)
    free(data_chain);
    free(data_lengths);

    if (total_length == 0) {
        // There was no data in the session to return.
        DBG(printf("Empty session:%p.\n", origin);)
        if (origin != NULL) {
            DBG(printf("Bleh\n");)
            free(origin);
        }
        return NULL;
    }

    // Set the the first packet in the session as our return value.
    origin->data = final_data;
    origin->len = total_length;

    DBG(printf("TCP assembly finished.\n");)
    DBG(printf("origin - ");) 
    DBG(tcp_print(origin);)

    return origin;
}

void tcp_save_state(config * conf) {
    FILE * outfile = fopen(conf->TCP_STATE_PATH,"w");
    tcp_info * next = conf->tcp_sessions_head;
    tcp_info * curr_pkt;

    if (outfile == NULL) {
        fprintf(stderr, "Could not open tcp state file.\n");
        fclose(outfile);
        return;
    }

    while (next != NULL) {
        curr_pkt = next;
        next = next->next_sess;
        while (curr_pkt != NULL) {
            tcp_info * prev_pkt = curr_pkt->prev_pkt;
            u_char * data = curr_pkt->data;
            size_t written;
            // Clear all or pointers, or turn them into flags.
            curr_pkt->next_sess = NULL;
            curr_pkt->next_pkt = NULL;
            // All we need to know is whether there is a prev. packet.
            curr_pkt->prev_pkt = (prev_pkt == NULL) ? (NULL+1) : NULL;
            curr_pkt->data = NULL;
            written = fwrite(curr_pkt, sizeof(tcp_info), 1, outfile);
            if (written != 1) {
                fprintf(stderr, "Could not write to tcp state file.\n");
                fclose(outfile);
                return;
            }
            written = fwrite(data, sizeof(u_char), curr_pkt->len, outfile);
            free(curr_pkt->data);
            free(curr_pkt);
            if (written != curr_pkt->len) {
                fprintf(stderr, "Could not write to tcp state file(data).\n");
                fclose(outfile);
                return;
            }
            curr_pkt = prev_pkt;
        }
    }
    fclose(outfile);
}

tcp_info * tcp_load_state(config * conf) {
    FILE * infile;
    struct stat i_stat;
    int ret = stat(conf->TCP_STATE_PATH, &i_stat);
    size_t read;
    tcp_info * pkt;
    tcp_info * prev = NULL;
    tcp_info * first_sess = NULL;
    tcp_info ** sess = &first_sess;
    int has_prev = 0;
 
    if (ret != 0) {
        // No prior state file.
        fprintf(stderr, "No prior tcp state file.\n");
        return NULL;
    }
    
    infile = fopen(conf->TCP_STATE_PATH, "r");
    if (infile == NULL) {
        fprintf(stderr, "Could not open existing tcp state file.\n");
        return NULL;
    }

    pkt = malloc(sizeof(tcp_info));
    read = fread(pkt, sizeof(tcp_info), 1, infile);
    while (read != 0) {
        // If the last packet had a another packet in the session,
        // then point it to this one and vice versa. 
        // Note: Don't forget the packets are in most recent first order.
        if (has_prev == 1) {
            prev->prev_pkt = pkt;
            pkt->next_pkt = prev;
        } else {
            // The last packet was the last in a session. 
            // Start a new session.
            *sess = pkt; 
            sess = &(pkt->next_sess);
        }
        has_prev = (pkt->prev_pkt == NULL);
        pkt->prev_pkt = NULL;
        
        pkt->data = malloc(sizeof(u_char) * pkt->len);
        read = fread(pkt->data, sizeof(u_char), pkt->len, infile);
        if (read != pkt->len) {
            // We are failing to free the memory of anything read in so far.
            // It's probably not a big deal.
            fprintf(stderr, "Tcp state file read error (data).\n");
            return NULL;
        }

        prev = pkt;
        pkt = malloc(sizeof(tcp_info));
        read = fread(pkt, sizeof(tcp_info), 1, infile);
    }

    // Since the last read was of length zero, (all other cases return or 
    // continue) go ahead and free our last allocated object.
    free(pkt);

    return first_sess;
}

void tcp_print(tcp_info * tcp) {
    if (tcp == NULL) {
        printf("NULL tcp object\n");
    } else {
        printf("%p %s:%d ", tcp, iptostr(&tcp->src), tcp->srcport);
        printf("-> %s:%d, seq: %x, safr: %d%d%d%d, len: %u\n", 
               iptostr(&tcp->dst), tcp->dstport,
               tcp->sequence, tcp->syn, tcp->ack,
               tcp->fin, tcp->rst, tcp->len);
    }
}

bpf_u_int32 parse_questions(bpf_u_int32 pos, bpf_u_int32 id_pos, 
                            struct pcap_pkthdr *header,
                            u_char *packet, u_short count, 
                            dns_question ** root) {
    bpf_u_int32 start_pos = pos; 
    dns_question * last = NULL;
    dns_question * current;
    u_short i;
    *root = NULL;

    for (i=0; i < count; i++) {
        current = malloc(sizeof(dns_question));
        current->next = NULL; current->name = NULL;

        current->name = read_rr_name(packet, &pos, id_pos, header->len);
        if (current->name == NULL || (pos + 2) >= header->len) {
            fprintf(stderr, "DNS question error\n");
            char * buffer = escape_data(packet, start_pos, header->len);
            const char * msg = "Bad DNS question: ";
            current->name = malloc(sizeof(char) * (strlen(buffer) +
                                                   strlen(msg) + 1));
            sprintf(current->name, "%s%s", msg, buffer);
            current->type = 0;
            current->cls = 0;
            if (last == NULL) *root = current;
            else last->next = current;
            return 0;
        }
        current->type = (packet[pos] << 8) + packet[pos+1];
        current->cls = (packet[pos+2] << 8) + packet[pos+3];

        if (last == NULL) *root = current;
        else last->next = current;
        last = current;
        pos = pos + 4;

        VERBOSE(printf("question->name: %s\n", current->name);)
        VERBOSE(printf("type %d, cls %d\n", current->type, current->cls);)
   }
    
    return pos;
}

// Parse an individual resource record, placing the acquired data in 'rr'.
// 'packet', 'pos', and 'id_pos' serve the same uses as in parse_rr_set.
// Return 0 on error, the new 'pos' in the packet otherwise.
bpf_u_int32 parse_rr(bpf_u_int32 pos, bpf_u_int32 id_pos, 
                     struct pcap_pkthdr *header, 
                     u_char *packet, dns_rr * rr,
                     config * conf) {
    int i;
    bpf_u_int32 rr_start = pos;
    rr_parser_container * parser;
    rr_parser_container opts_cont = {0,0, opts};

    bpf_u_int32 temp_pos; // Only used when parsing SRV records.
    char * temp_data; // Also used only for SRV records.

    rr->name = NULL;
    rr->data = NULL;
    
    rr->name = read_rr_name(packet, &pos, id_pos, header->len);
    // Handle a bad rr name.
    // We still want to print the rest of the escaped rr data.
    if (rr->name == NULL) {
        const char * msg = "Bad rr name: ";
        rr->name = malloc(sizeof(char) * (strlen(msg) + 1));
        sprintf(rr->name, "%s", "Bad rr name");
        rr->type = 0;
        rr->rr_name = NULL;
        rr->cls = 0;
        rr->ttl = 0;
        rr->data = escape_data(packet, pos, header->len);
        return 0;
    }
    
    if ((header->len - pos) < 10 ) return 0;
    
    rr->type = (packet[pos] << 8) + packet[pos+1];
    rr->rdlength = (packet[pos+8] << 8) + packet[pos + 9];
    // Handle edns opt RR's differently.
    if (rr->type == 41) {
        rr->cls = 0;
        rr->ttl = 0;
        rr->rr_name = "OPTS";
        parser = &opts_cont;
        // We'll leave the parsing of the special EDNS opt fields to
        // our opt rdata parser.  
        pos = pos + 2;
    } else {
        // The normal case.
        rr->cls = (packet[pos+2] << 8) + packet[pos+3];
        rr->ttl = 0;
        for (i=0; i<4; i++)
            rr->ttl = (rr->ttl << 8) + packet[pos+4+i];
        // Retrieve the correct parser function.
        parser = find_parser(rr->cls, rr->type);
        rr->rr_name = parser->name;
        pos = pos + 10;
    }

    VERBOSE(printf("Applying RR parser: %s\n", parser->name);)

    if (conf->MISSING_TYPE_WARNINGS && &default_rr_parser == parser) 
        fprintf(stderr, "Missing parser for class %d, type %d\n", 
                        rr->cls, rr->type);
    
    // Make sure the data for the record is actually there.
    // If not, escape and print the raw data.
    if (header->len < (rr_start + 10 + rr->rdlength)) {
        char * buffer;
        const char * msg = "Truncated rr: ";
        rr->data = escape_data(packet, rr_start, header->len);
        buffer = malloc(sizeof(char) * (strlen(rr->data) + strlen(msg) + 1));
        sprintf(buffer, "%s%s", msg, rr->data);
        free(rr->data);
        rr->data = buffer;
        return 0;
    }
    // Parse the resource record data.
    rr->data = parser->parser(packet, pos, id_pos, rr->rdlength, 
                              header->len);
    VERBOSE(
    printf("rr->name: %s\n", rr->name);
    printf("type %d, cls %d, ttl %d, len %d\n", rr->type, rr->cls, rr->ttl,
           rr->rdlength);
    printf("rr->data %s\n", rr->data);
    )

    return pos + rr->rdlength;
}

// Parse a set of resource records in the dns protocol in 'packet', starting
// at 'pos'. The 'id_pos' offset is necessary for putting together 
// compressed names. 'count' is the expected number of records of this type.
// 'root' is where to assign the parsed list of objects.
// Return 0 on error, the new 'pos' in the packet otherwise.
bpf_u_int32 parse_rr_set(bpf_u_int32 pos, bpf_u_int32 id_pos, 
                         struct pcap_pkthdr *header,
                         u_char *packet, u_short count, 
                         dns_rr ** root, config * conf) {
    dns_rr * last = NULL;
    dns_rr * current;
    u_short i;
    *root = NULL; 
    for (i=0; i < count; i++) {
        // Create and clear the data in a new dns_rr object.
        current = malloc(sizeof(dns_rr));
        current->next = NULL; current->name = NULL; current->data = NULL;
        
        pos = parse_rr(pos, id_pos, header, packet, current, conf);
        // If a non-recoverable error occurs when parsing an rr, 
        // we can only return what we've got and give up.
        if (pos == 0) {
            if (last == NULL) *root = current;
            else last->next = current;
            return 0;
        }
        if (last == NULL) *root = current;
        else last->next = current;
        last = current;
    }
    return pos;
}

// Generates a hash from the current packet. 
int dedup(bpf_u_int32 pos, struct pcap_pkthdr *header, u_char * packet,
          ip_info * ip, transport_info * trns, config * conf) {
    
    unsigned long long hash = 0;
    unsigned long long mask = 0xffffffffffffffff;
    bpf_u_int32 i;

    // Put the hash of the src address in the upper 32 bits,
    // and the dest in the lower 32.
    if (ip->src.vers == IPv4) {
        hash += ((unsigned long long)ip->src.addr.v4.s_addr << 32);
        hash += ip->dst.addr.v4.s_addr;
    } else {
        for (i=0; i<4; i++) {
            hash += (unsigned long long)ip->src.addr.v6.s6_addr32[i] << 32;
            hash += ip->dst.addr.v6.s6_addr32[i];
        }
    }
    hash += ((unsigned long long)trns->srcport << 32) + trns->dstport;
    
    // Add in the payload.
    for (; pos + 8 < header->len; pos+=8) {
        hash += *(unsigned long long*)(packet + pos);
    }   
    // Add in those last bytes, if any. 
    // Where doesn't matter, as long as we're consistent.
    for (; pos < header->len; pos++) {
        hash += packet[pos];
    }
    // Without this, all strings of nulls are equivalent.
    hash += header->len;
    // The hash is now done.

    if (hash == 0) {
        // Say it's not a duplicate even though it might be.
        // Since we initialize the dedup list to zero's, it's likely that
        // this will produce a false positive.
        return 0;
    }

    for (i=0; i < conf->DEDUPS; i++) {
        if (hash == conf->dedup_hashes[i]) {
            // Found a match, return the fact.
            return 1;
        }
    }
   
    // There was no match. Replace the oldest dedup.
    conf->dedup_hashes[conf->dedup_pos] = hash;
    conf->dedup_pos = (conf->dedup_pos + 1) % conf->DEDUPS;
    return 0;
}

// Parse the dns protocol in 'packet' starting at 'pos'. 
// The resulting data is placed in the given 'dns' struct.
// Return the new pos: 0 on error.
bpf_u_int32 dns_parse(bpf_u_int32 pos, struct pcap_pkthdr *header, 
                      u_char *packet, dns_info * dns,
                      config * conf) {
    
    int i;
    bpf_u_int32 id_pos = pos;
    dns_rr * last = NULL;

    if (header->len - pos < 12) {
        char * msg = escape_data(packet, id_pos, header->len);
        fprintf(stderr, "Truncated Packet(dns): %s\n", msg); 
        return 0;
    }
    
    dns->id = (packet[pos] << 8) + packet[pos+1];
    dns->qr = packet[pos+2] >> 7;
    dns->AA = (packet[pos+2] & 0x04) >> 2;
    dns->TC = (packet[pos+2] & 0x02) >> 1;
    dns->rcode = packet[pos + 3] & 0x0f;
    // rcodes > 5 indicate various protocol errors and redefine most of the 
    // remaining fields. Parsing this would hurt more than help. 
    if (dns->rcode > 5) {
        dns->qdcount = dns->ancount = dns->nscount = dns->arcount = 0;
        dns->queries = NULL;
        dns->answers = NULL;
        dns->name_servers = NULL;
        dns->additional = NULL;
        return pos + 12;
    }

    dns->qdcount = (packet[pos+4] << 8) + packet[pos+5];
    dns->ancount = (packet[pos+6] << 8) + packet[pos+7];
    dns->nscount = (packet[pos+8] << 8) + packet[pos+9];
    dns->arcount = (packet[pos+10] << 8) + packet[pos+11];

    SHOW_RAW(
        printf("dns\n");
        print_packet(header->len, packet, pos, header->len, 2);
    )
    VERBOSE(
        printf("DNS id:%d, qr:%d, AA:%d, TC:%d, rcode:%d\n", 
               dns->id, dns->qr, dns->AA, dns->TC, dns->rcode);
        printf("DNS qdcount:%d, ancount:%d, nscount:%d, arcount:%d\n",
               dns->qdcount, dns->ancount, dns->nscount, dns->arcount);
    )

    pos = parse_questions(pos+12, id_pos, header, packet, 
                          dns->qdcount, &(dns->queries));
    if (pos != 0) 
        pos = parse_rr_set(pos, id_pos, header, packet, 
                           dns->ancount, &(dns->answers), conf);
    else dns->answers = NULL;
    if (pos != 0 && (conf->NS_ENABLED || conf->AD_ENABLED)) {
        pos = parse_rr_set(pos, id_pos, header, packet, 
                           dns->nscount, &(dns->name_servers), conf);
    } else dns->name_servers = NULL;
    if (pos != 0 && conf->AD_ENABLED) {
        pos = parse_rr_set(pos, id_pos, header, packet, 
                           dns->arcount, &(dns->additional), conf);
    } else dns->additional = NULL;
    return pos;
}

// Print all resource records in the given section.
void print_rr_section(dns_rr * next, char * name, config * conf) {
    int skip;
    int i;
    while (next != NULL) {
        printf("%c%s", conf->SEP, name);
        skip = 0;
        for (i=0; i < conf->EXCLUDES && skip == 0; i++) 
            if (next->type == conf->EXCLUDED[i]) skip = 1;
        if (!skip) {
            char *name, *data;
            name = (next->name == NULL) ? "*empty*" : next->name;
            data = (next->data == NULL) ? "*empty*" : next->data;
            if (conf->PRINT_RR_NAME) { 
                if (next->rr_name == NULL) 
                    printf(" %s UNKNOWN(%d,%d) %s", name, next->type, 
                                                    next->cls, data);
                else
                    printf(" %s %s %s", name, next->rr_name, data);
            } else
                printf(" %s %d %d %s", name, next->type, next->cls, data);
        }
        next = next->next; 
    }
}
