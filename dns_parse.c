#include <getopt.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rtypes.h"
#include "types.h"
#include "strutils.h"

//#define VERBOSE
//#define SHOW_RAW

#define MAX_EXCLUDES 100

// Globals passed in via the command line.
// I don't really want these to be globals, but libpcap doesn't really 
// have the mechanism I need to pass them to the handler.
u_short EXCLUDED[MAX_EXCLUDES];
u_short EXCLUDES = 0;
char * MULTI_SEP = NULL;
// The Additional and Name server sections are disabled by default.
int AD_ENABLED = 0;
#include <string.h>
int NS_ENABLED = 0;
int PRETTY_DATE = 0;
int MISSING_TYPE_WARNINGS = 0;

void handler(u_char *, const struct pcap_pkthdr *, const u_char *);

typedef struct ipv4_info {
    u_char srcip[4];
    u_char dstip[4];
    u_short length;
    u_char proto;
} ipv4_info;
    
typedef struct udp_info {
    u_short srcport;
    u_short dstport;
    u_short length;
} udp_info;

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
    u_short ttl;
    u_short rdlength;
    u_short data_len;
    char * data;
    struct dns_rr * next;
} dns_rr;

typedef struct dns_header {
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
} dns_header;

int main(int argc, char **argv) {
    pcap_t * pcap_file;
    char errbuf[PCAP_ERRBUF_SIZE];
    int read;
    u_char * empty = "";
    
    int c;
    char *cvalue = NULL;
    int print_type_freq = 0;
    int arg_failure = 0;

    const char * OPTIONS = "dfhm:Mnux:";

    c = getopt(argc, argv, OPTIONS);
    while (c != -1) {
        switch (c) {
            case 'd':
                AD_ENABLED = 1;
                break;
            case 'f':
                print_parsers();
                return 0;
            case 'm':
                MULTI_SEP = optarg;
                break;
            case 'M':
                MISSING_TYPE_WARNINGS = 1;
                break;
            case 'n':
                NS_ENABLED = 1;
                break;
            case 't':
                PRETTY_DATE = 1; 
                break;
            case 'u':
                print_type_freq = 1;
                break;
            case 'x':
                if (EXCLUDES < MAX_EXCLUDES) {
                    int ival = atoi(optarg);
                    if (ival == 0 || ival >= 65536) {
                        fprintf(stderr, "Invalid excluded rtype value. "
                                "Value must be a short int.\n");
                        arg_failure = 1;
                    } else {
                        EXCLUDED[EXCLUDES] = ival;
                        EXCLUDES++; 
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
    read = pcap_dispatch(pcap_file, -1, (pcap_handler)handler, empty);
   
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

bpf_u_int32 parse_eth(const struct pcap_pkthdr *header, const u_char *packet) {
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

    #ifdef VERBOSE
    #ifdef SHOW_RAW
    printf("\neth ");
    print_packet(header, packet, 0, pos, 18);
    #endif
    printf("dstmac: %02x:%02x:%02x:%02x:%02x:%02x, "
           "srcmac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5],
           srcmac[0],srcmac[1],srcmac[2],srcmac[3],srcmac[4],srcmac[5]);
    #endif
    return pos;

}

bpf_u_int32 parse_ipv4(bpf_u_int32 pos, const struct pcap_pkthdr *header, 
                      const u_char *packet, ipv4_info * ipv4) {

    bpf_u_int32 version, h_len;
    int i;

    if (header-> len - pos < 20) {
        printf("Truncated Packet(ipv4)\n");
        return 0;
    }
    
    version = packet[pos] >> 4;
    h_len = packet[pos] & 0x0f;
    ipv4->length = (packet[pos+2] << 8) + packet[pos+3];
    ipv4->proto = packet[pos+9];

    for (i=0; i<4; i++) {
        ipv4->srcip[i] = packet[pos + 12 + i];
        ipv4->dstip[i] = packet[pos + 16 + i];
    }

    #ifdef VERBOSE
    #ifdef SHOW_RAW
    printf("\nipv4\n");
    print_packet(header, packet, pos, pos + 4*h_len, 4);
    #endif
    printf("version: %d, length: %d, proto: %d\n", 
            version, ipv4->length, ipv4->proto);
    printf("srcip: %d.%d.%d.%d, dstip: %d.%d.%d.%d\n",
           ipv4->srcip[0], ipv4->srcip[1], ipv4->srcip[2], ipv4->srcip[3],
           ipv4->dstip[0], ipv4->dstip[1], ipv4->dstip[2], ipv4->dstip[3]);
    #endif

    // move the position up past the options section.
    pos = pos + 4*h_len;
    return pos;
}

bpf_u_int32 parse_udp(bpf_u_int32 pos, const struct pcap_pkthdr *header, 
                      const u_char *packet, udp_info * udp) {
    u_short test;
    if (header->len - pos < 8) {
        printf("Truncated Packet(udp)\n");
        return 0;
    }

    udp->srcport = (packet[pos] << 8) + packet[pos+1];
    udp->dstport = (packet[pos+2] << 8) + packet[pos+3];
    udp->length = (packet[pos+4] << 8) + packet[pos+5];
    #ifdef VERBOSE
    #ifdef SHOW_RAW
    printf("udp\n");
    print_packet(header, packet, pos, pos + 8, 4);
    #endif
    printf("srcport: %d, dstport: %d, len: %d\n", udp->srcport, udp->dstport, 
                                                  udp->length);
    #endif
    return pos + 8;
}

bpf_u_int32 parse_questions(bpf_u_int32 pos, bpf_u_int32 id_pos, 
                            const struct pcap_pkthdr *header,
                            const u_char *packet, u_short count, 
                            dns_question ** root) {
    
    dns_question * last = NULL;
    dns_question * current;
    u_short i;
    *root = NULL;

    for (i=0; i < count; i++) {
        current = malloc(sizeof(dns_question));
        current->next = NULL; current->name = NULL;

        current->name = read_rr_name(packet, &pos, id_pos, header->len);
        if (current->name == NULL || (pos + 2) >= header->len) {
            dns_question_free(current);
            printf("Truncated Packet(dns question)\n");
            return 0;
        }
        current->type = (packet[pos] << 8) + packet[pos+1];
        current->cls = (packet[pos+2] << 8) + packet[pos+3];

        if (last == NULL) *root = current;
        else last->next = current;
        last = current;
        pos = pos + 4;

        #ifdef VERBOSE
        printf("question->name: %s\n", current->name);
        printf("type %d, cls %d\n", current->type, current->cls);
        #endif
   }
    
    return pos;
}

bpf_u_int32 parse_rr(bpf_u_int32 pos, bpf_u_int32 id_pos, 
                     const struct pcap_pkthdr *header, 
                     const u_char *packet, dns_rr * rr) {
    int i;
    bpf_u_int32 rr_start;
    rr_parser_container * parser;
    rr_parser_container opts_cont = {0,0, opts};

    bpf_u_int32 temp_pos; // Only used when parsing SRV records.
    char * temp_data; // Also used only for SRV records.

    rr->name = NULL;
    rr->data = NULL;
    
    rr->name = read_rr_name(packet, &pos, id_pos, header->len);
    if (pos == 0) return 0;
    
    if ((header->len - pos) < 10 ) return 0;

    rr->type = (packet[pos] << 8) + packet[pos+1];
    rr->rdlength = (packet[pos+8] << 8) + packet[pos + 9];
    // Handle edns opt RR's differently.
    switch (rr->type) {
        case 41:
            rr->cls = 0;
            rr->ttl = 0; 
            parser = &opts_cont;
            // We'll leave the parsing of the special EDNS opt fields to
            // our opt rdata parser.  
            rr_start = pos + 2;
            break;
        default:
            rr->cls = (packet[pos+2] << 8) + packet[pos+3];
            rr->ttl = 0;
            for (i=0; i<4; i++)
                rr->ttl = (rr->ttl << 8) + packet[pos+4+i];
            parser = find_parser(rr->cls, rr->type);
            rr_start = pos + 10;
    }

    if (MISSING_TYPE_WARNINGS && &default_rr_parser == parser) 
        fprintf(stderr, "Missing parser for class %d, type %d\n", 
                        rr->cls, rr->type);

    if ((header->len - pos) < (10 + rr->rdlength)) return 0;
    rr->data = parser->parser(packet, pos+10, id_pos, rr->rdlength, 
                              header->len);

    #ifdef VERBOSE
    printf("rr->name: %s\n", rr->name);
    printf("type %d, cls %d, ttl %d, len %d\n", rr->type, rr->cls, rr->ttl,
           rr->rdlength);
    printf("rr->data %s\n", rr->data);
    #endif

    return pos + 10 + rr->rdlength;
}

bpf_u_int32 parse_rr_set(bpf_u_int32 pos, bpf_u_int32 id_pos, 
                         const struct pcap_pkthdr *header,
                         const u_char *packet, u_short count, 
                         dns_rr ** root) {
    dns_rr * last = NULL;
    dns_rr * current;
    u_short i;
    *root = NULL; 

    for (i=0; i < count; i++) {
        current = malloc(sizeof(dns_rr));
        current->next = NULL; current->name = NULL; current->data = NULL;
        
        pos = parse_rr(pos, id_pos, header, packet, current);
        if (pos == 0) {
            dns_rr_free(current);
            printf("Truncated Packet(dns rr)\n");
            return 0;
        }
        if (last == NULL) *root = current;
        else last->next = current;
        last = current;
    }
    return pos;
}

bpf_u_int32 parse_dns(bpf_u_int32 pos, const struct pcap_pkthdr *header, 
                      const u_char *packet, dns_header * dns) {
    
    int i;
    bpf_u_int32 id_pos = pos;
    dns_rr * last = NULL;

    if (header->len - pos < 12) {
        printf("Truncated Packet(dns)\n");
        return 0;
    }

    dns->id = (packet[pos] << 8) + packet[pos+1];
    dns->qr = packet[pos+2] >> 7;
    dns->AA = (packet[pos+2] & 0x04) >> 2;
    dns->TC = (packet[pos+2] & 0x02) >> 1;
    dns->rcode = packet[pos + 3] & 0x0f;
    dns->qdcount = (packet[pos+4] << 8) + packet[pos+5];
    dns->ancount = (packet[pos+6] << 8) + packet[pos+7];
    dns->nscount = (packet[pos+8] << 8) + packet[pos+9];
    dns->arcount = (packet[pos+10] << 8) + packet[pos+11];
    
    #ifdef VERBOSE
    #ifdef SHOW_RAW
    printf("dns\n");
    print_packet(header, packet, pos, header->len, 2);
    #endif
    printf("DNS id:%d, qr:%d, AA:%d, TC:%d, rcode:%d\n", 
           dns->id, dns->qr, dns->AA, dns->TC, dns->rcode);
    printf("DNS qdcount:%d, ancount:%d, nscount:%d, arcount:%d\n",
           dns->qdcount, dns->ancount, dns->nscount, dns->arcount);
    #endif

    pos = parse_questions(pos+12, id_pos, header, packet, 
                       dns->qdcount, &(dns->queries));
    if (pos == 0) return 0;
    pos = parse_rr_set(pos, id_pos, header, packet, 
                       dns->ancount, &(dns->answers));
    if (pos == 0) return 0;
    if (NS_ENABLED || AD_ENABLED) {
        pos = parse_rr_set(pos, id_pos, header, packet, 
                           dns->nscount, &(dns->name_servers));
        if (pos == 0) return 0;
    } else dns->name_servers = NULL;
    if (AD_ENABLED) {
        pos = parse_rr_set(pos, id_pos, header, packet, 
                           dns->arcount, &(dns->additional));
        if (pos == 0) return 0;
    } else dns->additional = NULL;
    return pos;
}

void print_rr_section(dns_rr * next, char * name, char sep) {
    int skip;
    int i;
    if (next != NULL) printf("%c%s", sep, name);
    while (next != NULL) {
        skip = 0;
        for (i=0; i < EXCLUDES && skip == 0; i++) 
            if (next->type == EXCLUDED[i]) skip = 1;
        
        if (!skip)  
            printf("%c%s %d %d %s", sep, next->name, next->type, next->cls,
                                    next->data);
        next = next->next; 
    }
}

void handler(u_char * args, const struct pcap_pkthdr *header, 
             const u_char *packet) {
    int pos;
    struct ipv4_info ipv4;
    struct udp_info udp;
    struct dns_header dns;

    char sep;
    char * record_sep;

    char date[200];
    char proto;
    bpf_u_int32 dnslength;
    struct dns_rr *next;
    struct dns_question *qnext;

    #ifdef VERBOSE
    printf("\nPacket %d.%d\n", header->ts.tv_sec, header->ts.tv_usec);
    #endif

    pos = parse_eth(header, packet);
    if (pos == 0) return;
    pos = parse_ipv4(pos, header, packet, &ipv4);
    if ( pos == 0) return;
    if (ipv4.proto != 17) {
        printf("Unsupported Protocol(%d)\n", ipv4.proto);
        return;
    }
    
    pos = parse_udp(pos, header, packet, &udp);
    if ( pos == 0 ) return;

    pos = parse_dns(pos, header, packet, &dns);
    if ( pos == 0 ) return;

    if (PRETTY_DATE) {
        struct tm *time;
        size_t result;
        const char * format = "%D %T";
        time = gmtime(&(header->ts.tv_sec));
        result = strftime(date, 200, format, time);
        if (result == 0) strncpy(date, "Date format error", 20);
    } else 
        sprintf(date, "%d.%06d", header->ts.tv_sec, header->ts.tv_usec);
   
    if (MULTI_SEP == NULL) {
        sep = '\t';
        record_sep = "\n";
    } else {
        sep = '\n';
        record_sep = MULTI_SEP;
    }

    if (ipv4.proto == 17) {
        proto = 'u';
        dnslength = udp.length;
    } else if (ipv4.proto == 6) {
        proto = 't';
        dnslength = 0;
    } else {    
        proto = '?';
        dnslength = 0;
    }
    
    printf("%s,%d.%d.%d.%d,%d.%d.%d.%d,%d,%c,%c,%s", date,  
           ipv4.srcip[0], ipv4.srcip[1], ipv4.srcip[2], ipv4.srcip[3],
           ipv4.dstip[0], ipv4.dstip[1], ipv4.dstip[2], ipv4.dstip[3],
           dnslength, proto, dns.qr ? 'r':'q', dns.AA?"AA":"");
    qnext = dns.queries;
    if (qnext != NULL) printf("%cQueries", sep);
    while (qnext != NULL) {
        printf("%c%s %d %d", sep, qnext->name, qnext->type, qnext->cls);
        qnext = qnext->next; 
    }

    print_rr_section(dns.answers, "Answers", sep);
    if (NS_ENABLED) print_rr_section(dns.name_servers, "Name Servers", sep);
    if (AD_ENABLED) print_rr_section(dns.additional, "Additional", sep);
    printf("%c%s\n", sep, record_sep);

    dns_question_free(dns.queries);
    dns_rr_free(dns.answers);
    dns_rr_free(dns.name_servers);
    dns_rr_free(dns.additional);
}
