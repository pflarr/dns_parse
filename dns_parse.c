#include <arpa/inet.h>
#include <getopt.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rtypes.h"
#include "types.h"
#include "strutils.h"


// Verbosity flags. Switch which function is defined to add or remove
// various output printfs from the source. These are all for debugging
// purposes.
//#define VERBOSE(A) A
#define VERBOSE(A)
//#define DBG(A) A fflush(stdout);
#define DBG(A)
//#define SHOW_RAW(A) A
#define SHOW_RAW(A) 

#define eprintf(format, ...) fprintf(stderr, format, __VA_ARGS__)

// Get the value of the BITth bit from byte offset O bytes from base B.
#define GET_BIT(B,O,BIT) (unsigned char)(((*(B+O)) & (1 << (BIT))) >> BIT )
// Get a two byte little endian u_int at base B and offset O.
#define LE_U_SHORT(B,O) (u_short)((B[O]<<8)+B[O+1])
// Get a four byte little endian u_int at base B and offset O.
#define LE_U_INT(B,O) (bpf_u_int32)((B[O]<<24)+(B[O+1]<<16)+(B[O+2]<<8)+B[O+3])
// Get the DNS tcp length prepended field.
#define TCP_DNS_LEN(P,O) ((P[O]<<8) + P[O+1])

void dbg_free(void * ptr) {
//    printf("Freeing %p\n", ptr);
    free(ptr);
}

// We'll be passing the 'config' structure * through as the last 
// argument in a pretty hackish way.
void handler(u_char *, const struct pcap_pkthdr *, const u_char *);

typedef union {
    struct in_addr v4;
    struct in6_addr v6;
} ip_shared;

typedef struct {
    u_char version;
    ip_shared srcip;
    ip_shared dstip;
    u_short length;
    u_char proto;
} ip_info;

enum transport_type {
    UDP,
    TCP
};

typedef struct {
    u_short srcport;
    u_short dstport;
    u_short length;
    enum transport_type transport; 
} transport_info;

typedef struct tcp_info {
    struct timeval ts;
    ip_shared srcip;
    ip_shared dstip;
    u_short srcport;
    u_short dstport;
    bpf_u_int32 sequence;
    bpf_u_int32 ack_num;
    bpf_u_int32 len;
    u_char syn;
    u_char ack;
    u_char fin;
    u_char rst;
    u_char * data;
    size_t data_len;
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
    tcp_info * tcp_sessions_head;
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

int main(int argc, char **argv) {
    pcap_t * pcap_file;
    char errbuf[PCAP_ERRBUF_SIZE];
    int read;
    config conf;
    
    int c;
    char *cvalue = NULL;
    int print_type_freq = 0;
    int arg_failure = 0;

    const char * OPTIONS = "dfhm:Mnurtx:";

    // Setting configuration defaults.
    conf.EXCLUDES = 0;
    conf.RECORD_SEP = "";
    conf.SEP = '\t';
    conf.AD_ENABLED = 0;
    conf.NS_ENABLED = 0;
    conf.PRETTY_DATE = 0;
    conf.PRINT_RR_NAME = 0;
    conf.MISSING_TYPE_WARNINGS = 0;
    conf.tcp_sessions_head = NULL;

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
            case 't':
                conf.PRETTY_DATE = 1; 
                break;
            case 'u':
                print_type_freq = 1;
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

    if (optind == argc - 1) {
        pcap_file = pcap_open_offline(argv[optind], errbuf);
        if (pcap_file == NULL) {
            printf("Could not open pcapfile.\n%s\n", errbuf);
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
        "Usage: dns_parse [-dnthf] [-m<query sep.>] [-x<rtype>] <pcap file>\n"
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
        "a tab (a newline in multiline mode). Each section of records\n"
        "is preceeded by a separate record containing only the section name:\n"
        "(Questions, Answers, Name Servers, Additional)\n"
        "By default the resource record format is:\n"
        "<name> <type> <class> <rdata>\n\n"
        "Query records are the same, except without the <rdata>\n"
        "The rdata is parsed by a custom parser that depends on the\n"
        "record type and class. Use the -f option to get a list of\n"
        "the supported record types and documentation on the parsers.\n\n"
        "Args:\n"
        "<pcapfile> - The pcapfile to parse. Use a '-' for stdin\n"
        "-d\n"
        "   Enable the parsing and output of the Additional\n"
        "   Records section. Disabled by default.\n"
        "-f\n"
        "   Print out documentation on the various resource \n"
        "   record parsers.\n"
        "-n\n"
        "   Enable the parsing and output of the Name Server\n"
        "   Records section. Disabled by default.\n"
        "-m \n"
        "   Multiline mode. Reservation records are newline\n"
        "   separated, and the whole record ends with the\n"
        "   separator given.\n"
        "-M \n"
        "   Print a message for each occurance of a missing class,type\n"
        "   parser.\n"
        "-r \n"
        "   Changes the resource record format to: \n"
        "   <name> <rr_type_name> <rdata>\n"
        "   If the record type isn't known, 'UNKNOWN(<cls>,<type>)' is given\n"
        "   The query record format is the similar, but missing the rdata.\n"
        "-t \n"
        "   Print the time/date as in Y/M/D H:M:S format.\n"
        "   The time will be in the local timezone.\n"
        "-u \n"
        "   Print a record of the how many occurances of each class,type\n"
        "   record occurred via stderr when processing completes.\n"
        "-x\n"
        "   Exclude the given reservation record types by \n"
        "   number. This option can be given multiple times.\n"
                        );
        return -1;
    }
 
    // need to check this for overflow.
    read = pcap_dispatch(pcap_file, -1, (pcap_handler)handler, 
                         (u_char *) &conf);

    int tcp_left = 0;
    tcp_info * curr = conf.tcp_sessions_head;
    while (curr != NULL) {
        tcp_info * next = curr->next_sess;
        tcp_info * tmp;
        while (curr != NULL) {
            tmp = curr;
            curr = curr->prev_pkt;
            dbg_free(tmp->data);
            dbg_free(tmp);
            tcp_left++;
        }
        curr = next;
    }
    DBG(printf("Unexpired TCP sessions: %d\n", tcp_left);)
    if (print_type_freq) print_parser_usage();
    
    return 0;
}

void print_packet(const struct pcap_pkthdr *header, const u_char *packet,
                  bpf_u_int32 start, bpf_u_int32 end, u_int wrap) {
    int i=0;
    while (i < end - start && (i + start) < header->len) {
        printf("%02x ", packet[i+start]);
        i++;
        if ( i % wrap == 0) printf("\n");
    }
    if ( i % wrap != 0) printf("\n");
    return;
}

void dns_rr_free(dns_rr * rr) {
    if (rr == NULL) return;
    if (rr->name != NULL) dbg_free(rr->name);
    if (rr->data != NULL) dbg_free(rr->data);
    dns_rr_free(rr->next);
    dbg_free(rr);
}

void dns_question_free(dns_question * question) {
    if (question == NULL) return;
    if (question->name != NULL) dbg_free(question->name);
    dns_question_free(question->next);
    dbg_free(question);
}

bpf_u_int32 eth_parse(const struct pcap_pkthdr *header, const u_char *packet) {
    u_char dstmac[6], srcmac[6];
    bpf_u_int32 pos = 0;

    int i;

    if (header->len < 14) {
        printf("Truncated Packet(eth)\n");
        return 0;
    }

    while (pos < 6) {
        dstmac[pos] = packet[pos];
        srcmac[pos] = packet[pos+6];
        pos++;
    }
    pos = pos + 6;

    // Skip VLAN tagging 
    if (packet[pos] == 0x81 && packet[pos+1] == 0) pos = pos + 4;

    if (packet[pos] != 0x08 || packet[pos+1] != 0) {
        printf("Unsupported EtherType: %02x%02x\n", packet[pos], 
                                                    packet[pos+1]);
        for (i=0; i<pos+2; i++) 
            printf("%02x ", packet[i]);
        printf("\n");
        return 0;
    }
    pos = pos + 2;

    SHOW_RAW(
        printf("\neth ");
        print_packet(header, packet, 0, pos, 18);
    )
    VERBOSE(
        printf("dstmac: %02x:%02x:%02x:%02x:%02x:%02x, "
               "srcmac: %02x:%02x:%02x:%02x:%02x:%02x\n",
               dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5],
               srcmac[0],srcmac[1],srcmac[2],srcmac[3],srcmac[4],srcmac[5]);
    )
    return pos;

}

bpf_u_int32 parse_ipv4(bpf_u_int32 pos, const struct pcap_pkthdr *header, 
                      const u_char *packet, ip_info * ip) {

    bpf_u_int32 version, h_len;
    int i;

    if (header-> len - pos < 20) {
        printf("Truncated Packet(ipv4)\n");
        return 0;
    }
    
    version = packet[pos] >> 4;
    h_len = packet[pos] & 0x0f;
    ip->length = (packet[pos+2] << 8) + packet[pos+3] - h_len*4;
    ip->proto = packet[pos+9];

    ip->srcip.v4.s_addr = *(in_addr_t *)(packet + pos + 12);
    ip->dstip.v4.s_addr = *(in_addr_t *)(packet + pos + 16);

    SHOW_RAW(
        printf("\nipv4\n");
        print_packet(header, packet, pos, pos + 4*h_len, 4);
    )
    VERBOSE(
        printf("version: %d, length: %d, proto: %d\n", 
                version, ip->length, ip->proto);
        printf("srcip: %s, ", inet_ntoa(ip->srcip.v4));
        printf("dstip: %s\n", inet_ntoa(ip->dstip.v4));
    )

    // move the position up past the options section.
    pos = pos + 4*h_len;
    return pos;
}

bpf_u_int32 udp_parse(bpf_u_int32 pos, const struct pcap_pkthdr *header, 
                      const u_char *packet, transport_info * udp, 
                      config * conf) {
    u_short test;
    if (header->len - pos < 8) {
        printf("Truncated Packet(udp)\n");
        return 0;
    }

    udp->srcport = (packet[pos] << 8) + packet[pos+1];
    udp->dstport = (packet[pos+2] << 8) + packet[pos+3];
    udp->length = (packet[pos+4] << 8) + packet[pos+5];
    udp->transport = UDP;
    VERBOSE(printf("udp\n");)
    VERBOSE(printf("srcport: %d, dstport: %d, len: %d\n", udp->srcport, udp->dstport, udp->length);)
    SHOW_RAW(print_packet(header, packet, pos, pos, 4);)
    return pos + 8;
}

u_short tcp_checksum(ip_info *ip, const u_char *packet, 
                     bpf_u_int32 pos, const struct pcap_pkthdr *header) {
    unsigned int sum = 0;
    unsigned int i;
    bpf_u_int32 srcip = ip->srcip.v4.s_addr; 
    bpf_u_int32 dstip = ip->dstip.v4.s_addr; 
  
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

#define TCP_EXPIRE_USECS 500000
#define __USEC_RES 1000000
#define is_expired(now, old) (\
    ((long long) (now).tv_sec*__USEC_RES + (now).tv_usec) - \
    ((long long) (old).tv_sec*__USEC_RES + (old).tv_usec)) > \
      TCP_EXPIRE_USECS

void tcp_parse(bpf_u_int32 pos, const struct pcap_pkthdr *header, 
               const u_char *packet, ip_info *ip, config * conf) {
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
    tcp->srcip = ip->srcip;
    tcp->dstip = ip->dstip;
    tcp->srcport = LE_U_SHORT(packet, pos);
    tcp->dstport = LE_U_SHORT(packet, pos+2);
    tcp->sequence = LE_U_INT(packet, pos + 4);
    tcp->ack_num = LE_U_INT(packet, pos + 8);
    tcp->ack = GET_BIT(packet, pos + 13, 5);
    tcp->syn = GET_BIT(packet, pos + 13, 1);
    tcp->fin = GET_BIT(packet, pos + 13, 0);
    tcp->rst = GET_BIT(packet, pos + 13, 2);
    offset = packet[pos + 12] >> 4;
    DBG(printf("Done some.\n");)

    if ((pos + offset*4) > header->len) {
        fprintf(stderr, "Truncated TCP packet: %d, %d\n", offset, header->len);
        dbg_free(tcp);
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
        dbg_free(tcp);
        return;
    } else if (checksum == 0x0000 && tcp->rst) {
        // Ignore, since it's a reset packet.
    }
    
    DBG(printf("Checksummed.\n");)

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
        if ( (*next)->srcip.v4.s_addr == tcp->srcip.v4.s_addr &&
             (*next)->dstip.v4.s_addr == tcp->dstip.v4.s_addr &&
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
// Each session is put through the assembly process, which does the 
// best it can (basically up to the first missing packet).
// Returns a tcp_info pointer that is the head of a list of all expired
// sessions.
tcp_info * tcp_expire(config * conf, const struct timeval * now ) {
    tcp_info * ret = NULL;
    tcp_info ** ptr = &ret;
    tcp_info ** next = &(conf->tcp_sessions_head);

    while (*next != NULL) {
        // Check to see if this session is expired based on the time given.
        if (is_expired(*now, (*next)->ts)) {
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
    
    tcp_info * c_next = ret;
    bpf_u_int32 sess_total = 0;
    while (c_next != NULL) {
        sess_total++;
        c_next = c_next->next_sess;
    }
    DBG(printf("Sessions expired: %d\n", sess_total);)


    return ret;
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
        // If we didn't find a matching packet with data, you the least
        // recent zero length packet. If that should be the origin, but 
        // isn't, adjust the origin packet.
        if (*curr == NULL && next_best != NULL) {
            if (*next_best != NULL) {
                if (origin->sequence == (*next_best)->sequence) {
                    origin = *next_best;
                }
                curr = next_best;
            }
        }
 
        if (*curr != NULL) {
            DBG(printf("Current assembly packet: ");)
            DBG(tcp_print(*curr);)
            tcp_info * tmp;
            struct pcap_pkthdr fakeit; //XXX
            fakeit.len = (*curr)->len;
            DBG(print_packet((const struct pcap_pkthdr *)&fakeit,
                             (*curr)->data, 0, (*curr)->len, 8);)
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
                dbg_free(tmp);
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
        dbg_free(base->data);
        dbg_free(base);
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
                dbg_free(data_chain[i]);
            }
        }
    }

    DBG(printf("data_chain, lengths, free.\n");)
    dbg_free(data_chain);
    dbg_free(data_lengths);

    if (total_length == 0) {
        // There was no data in the session to return.
        DBG(printf("Empty session:%p.\n", origin);)
        if (origin != NULL) {
            DBG(printf("Bleh\n");)
            dbg_free(origin);
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

void tcp_print(tcp_info * tcp) {
    if (tcp == NULL) {
        printf("NULL tcp object\n");
    } else {
        printf("%p %s:%d ", tcp, inet_ntoa(tcp->srcip.v4), tcp->srcport);
        printf("-> %s:%d, seq: %x, safr: %d%d%d%d, len: %u\n", 
               inet_ntoa(tcp->dstip.v4), tcp->dstport,
               tcp->sequence, tcp->syn, tcp->ack,
               tcp->fin, tcp->rst, tcp->len);
    }
}

bpf_u_int32 parse_questions(bpf_u_int32 pos, bpf_u_int32 id_pos, 
                            const struct pcap_pkthdr *header,
                            const u_char *packet, u_short count, 
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

bpf_u_int32 parse_rr(bpf_u_int32 pos, bpf_u_int32 id_pos, 
                     const struct pcap_pkthdr *header, 
                     const u_char *packet, dns_rr * rr,
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
    switch (rr->type) {
        case 41:
            rr->cls = 0;
            rr->ttl = 0;
            rr->rr_name = "OPTS";
            parser = &opts_cont;
            // We'll leave the parsing of the special EDNS opt fields to
            // our opt rdata parser.  
            pos = pos + 2;
            break;
        default:
            rr->cls = (packet[pos+2] << 8) + packet[pos+3];
            rr->ttl = 0;
            for (i=0; i<4; i++)
                rr->ttl = (rr->ttl << 8) + packet[pos+4+i];
            parser = find_parser(rr->cls, rr->type);
            rr->rr_name = parser->name;
            pos = pos + 10;
    }

    VERBOSE(printf("Applying RR parser: %s\n", parser->name);)

    if (conf->MISSING_TYPE_WARNINGS && &default_rr_parser == parser) 
        fprintf(stderr, "Missing parser for class %d, type %d\n", 
                        rr->cls, rr->type);

    if (header->len < (rr_start + 10 + rr->rdlength)) {
        char * buffer;
        const char * msg = "Truncated rr: ";
        rr->data = escape_data(packet, rr_start, header->len);
        buffer = malloc(sizeof(char) * (strlen(rr->data) + strlen(msg) + 1));
        sprintf(buffer, "%s%s", msg, rr->data);
        dbg_free(rr->data);
        rr->data = buffer;
        return 0;
    }
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

bpf_u_int32 parse_rr_set(bpf_u_int32 pos, bpf_u_int32 id_pos, 
                         const struct pcap_pkthdr *header,
                         const u_char *packet, u_short count, 
                         dns_rr ** root, config * conf) {
    dns_rr * last = NULL;
    dns_rr * current;
    u_short i;
    *root = NULL; 
    for (i=0; i < count; i++) {
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

bpf_u_int32 dns_parse(bpf_u_int32 pos, const struct pcap_pkthdr *header, 
                      const u_char *packet, dns_info * dns,
                      config * conf) {
    
    int i;
    bpf_u_int32 id_pos = pos;
    dns_rr * last = NULL;

    if (header->len - pos < 12) {
        printf("header length: %d\n", header->len);
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
        print_packet(header, packet, pos, header->len, 2);
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

// Parse and output a packet's DNS data.
void print_summary(ip_info * ip, transport_info * trns, dns_info * dns,
                   const struct pcap_pkthdr * header, config * conf) {
    char date[200];
    char proto;

    bpf_u_int32 dnslength;
    dns_rr *next;
    dns_question *qnext;

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
   
    if (ip->proto == 17) {
        proto = 'u';
        dnslength = trns->length;
    } else if (ip->proto == 6) {
        proto = 't';
        dnslength = trns->length;
    } else {    
        proto = '?';
        dnslength = 0;
    }
    
    fflush(stdout);
    printf("%s,%s,", date, inet_ntoa(ip->srcip.v4));
    printf("%s,%d,%c,%c,%s", inet_ntoa(ip->dstip.v4),
           dnslength, proto, dns->qr ? 'r':'q', dns->AA?"AA":"NA");
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

void handler(u_char * args, const struct pcap_pkthdr *header, 
             const u_char *packet) {
    int pos;
    ip_info ip;
    config * conf = (config *) args;
    
    VERBOSE(printf("\nPacket %llu.%llu\n", 
                   (unsigned long long)header->ts.tv_sec, 
                   (unsigned long long)header->ts.tv_usec);)

    pos = eth_parse(header, packet);
    if (pos == 0) return;
    pos = parse_ipv4(pos, header, packet, &ip);
    if ( pos == 0) return;
    if (ip.proto == 17) {
        dns_info dns;
        transport_info udp;
        pos = udp_parse(pos, header, packet, &udp, conf);
        if ( pos == 0 ) return;
        pos = dns_parse(pos, header, packet, &dns, conf);
        print_summary(&ip, &udp, &dns, header, conf);
    } else if (ip.proto == 6) {
        DBG(printf("TCP packet.\n");)
        // This doesn't return anything. We parse sessions as they expire,
        // not as they complete.
        tcp_parse(pos, header, packet, &ip, conf); 
        DBG(printf("Done parsing TCP.\n");)
    } else {
        fprintf(stderr, "Unsupported Protocol(%d)\n", ip.proto);
        return;
    }
   
    // Get any complete or expired TCP sessions.
    DBG(printf("Expiring TCP.\n");)
    tcp_info * tcp = tcp_expire(conf, &header->ts);
    while (tcp != NULL) {
        tcp_info * tmp;
        bpf_u_int32 size = (tcp->data[0] << 8) + tcp->data[1];
        
        // There is a possiblity that this session won't start at the
        // the beginning of the data; that we've caught a session mid-stream.
        // Assuming we have expired it at a reasonable end, we can use the 
        // length bytes to test our start position. If our length bytes allow
        // us to correctly jump the length of the packet, then we're good.
        unsigned long long tcp_offset;
        unsigned long long tcp_dns_len;
        char tcp_offset_found = 0;
        for (tcp_offset=0; tcp_offset < tcp->len-1; tcp_offset++) {
            unsigned long long tcp_pos = tcp_offset;
            while (tcp_pos < tcp->len) {
                tcp_dns_len = TCP_DNS_LEN(tcp->data, tcp_pos);
                // We shouldn't ever have an offset of 0.
                if (tcp_dns_len == 0) break;
                tcp_pos += 2 + tcp_dns_len;
            }
            // We've found the right tcp_offset (probably 0).
            if (tcp_pos == tcp->len) {
                tcp_offset_found = 1;
                break;
            }
        }
        
        if (tcp_offset_found == 0) {
            if (TCP_DNS_LEN(tcp->data, 0) < tcp->len &&
                TCP_DNS_LEN(tcp->data, 0) > 12 ) {
                // Try a tcp_offset of 0, just in case.
                tcp_offset = 0;
            } else { 
                fprintf(stderr, "Could not find beginning of TCP stream.\n");
            }
        }

        tcp_dns_len = TCP_DNS_LEN(tcp->data, tcp_offset);
        while (tcp_offset + tcp_dns_len < tcp->len) {
            dns_info dns;
            transport_info trns;
            tcp_info * tmp;
            struct pcap_pkthdr fake_header;

            fake_header.ts = tcp->ts;
            fake_header.caplen = tcp->len;
            fake_header.len = tcp->len;
            trns.srcport = tcp->srcport;
            trns.dstport = tcp->dstport;
            trns.length = tcp->len;
            trns.transport = TCP;
            ip.srcip.v4.s_addr = tcp->srcip.v4.s_addr;
            ip.dstip.v4.s_addr = tcp->dstip.v4.s_addr;
            DBG(printf("Parsing DNS (TCP).\n");)
            pos = dns_parse(tcp_offset + 2, &fake_header, 
                            tcp->data, &dns, conf);
            DBG(printf("Printing summary (TCP).\n");)
            print_summary(&ip, &trns, &dns, &fake_header, conf);
            DBG(printf("Done with summary (TCP).\n");)
            
            if (pos != tcp_offset + 2 + tcp_dns_len) {
                DBG(printf("Mismatched lengths.\n");)
            }
            tcp_offset += 2 + tcp_dns_len;
            if (tcp_offset < tcp->len) {
                // We don't want to try to parse the length if we're past
                // the end of the packet.
                tcp_dns_len = TCP_DNS_LEN(tcp->data, tcp_offset);
            }
        }

        tmp = tcp;
        tcp = tcp->next_sess;
        dbg_free(tmp->data);
        dbg_free(tmp);
    }
    DBG(printf("Done with packet.\n");)
}
