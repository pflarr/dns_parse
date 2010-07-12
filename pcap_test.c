#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include "rtypes.h"
#include "types.h"
#include "strutils.h"

#define VERBOSE
//#define SHOW_RAW

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

int main() {
    pcap_t * pcap_file;
    char * errors;
    int read;
    u_char * empty = "";
   
    pcap_file = pcap_open_offline("current", errors);

    read = pcap_dispatch(pcap_file, 30000, (pcap_handler)handler, empty);
    
    printf("done\n");
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
    if (rr->name != NULL) free(rr->name);
    if (rr->data != NULL) free(rr->data);
    if (rr->next != NULL) dns_rr_free(rr->next);
    free(rr);
}

void dns_question_free(dns_question * question) {
    if (question->name != NULL) free(question->name);
    if (question->next != NULL) free(question->next);
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
                            dns_question * root) {
    
    dns_question * last = NULL;
    dns_question * current;
    u_short i;

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

        if (last == NULL) root = current;
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
    rr_parser_container * parser;
    rr->name = NULL;
    rr->data = NULL;
    
    rr->name = read_rr_name(packet, &pos, id_pos, header->len);
    if (pos == 0) return 0;
    
    if ((header->len - pos) < 10 ) return 0;

    rr->type = (packet[pos] << 8) + packet[pos+1];
    rr->rdlength = (packet[pos+8] << 8) + packet[pos + 9];
    // Handle edns opt RR's differently.
    if (rr->type == 41) {
        rr->cls = 0;
        rr->ttl = 0; 
        parser = find_parser(0,41);
        // We'll leave the parsing of the special EDNS opt fields to
        // our opt rdata parser.  
        rr->data = parser->parser(packet, pos+2, id_pos, rr->rdlength,
                                  header->len);
    } else {
        rr->cls = (packet[pos+2] << 8) + packet[pos+3];
        rr->ttl = 0;
        for (i=0; i<4; i++)
            rr->ttl = (rr->ttl << 8) + packet[pos+4+i];
        if ((header->len - pos) < (10 + rr->rdlength)) return 0;

        parser = find_parser(rr->cls, rr->type);
        rr->data = parser->parser(packet, pos+10, id_pos, rr->rdlength, 
                                  header->len);
    }
    
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
                         const u_char *packet, u_short count, dns_rr * root) {
    dns_rr * last = NULL;
    dns_rr * current;
    u_short i;

    for (i=0; i < count; i++) {
        current = malloc(sizeof(dns_rr));
        current->next = NULL; current->name = NULL; current->data = NULL;
        
        pos = parse_rr(pos, id_pos, header, packet, current);
        if (pos == 0) {
            dns_rr_free(current);
            printf("Truncated Packet(dns rr)\n");
            return 0;
        }
        if (last == NULL) root = current;
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
                       dns->qdcount, dns->queries);
    if (pos == 0) return 0;
    pos = parse_rr_set(pos, id_pos, header, packet, 
                       dns->ancount, dns->answers);
    if (pos == 0) return 0;
    pos = parse_rr_set(pos, id_pos, header, packet, 
                       dns->nscount, dns->name_servers);
    if (pos == 0) return 0;
    pos = parse_rr_set(pos, id_pos, header, packet, 
                       dns->arcount, dns->additional);
    if (pos == 0) return 0;

    return pos;
}

void handler(u_char * args, const struct pcap_pkthdr *header, 
             const u_char *packet) {
    int pos;
    u_char proto;
    struct ipv4_info ipv4;
    struct udp_info udp;
    struct dns_header dns;

    #ifdef VERBOSE
    printf("\nPacket %d.%d\n", header->ts.tv_sec, header->ts.tv_usec);
    #endif

    pos = parse_eth(header, packet);
    if (pos == 0) return;
    pos = parse_ipv4(pos, header, packet, &ipv4);
    if ( pos == 0) return;
    if (ipv4.proto != 17) {
        printf("Unsupported Protocol(%d)", ipv4.proto);
        return;
    }
    
    pos = parse_udp(pos, header, packet, &udp);
    if ( pos == 0 ) return;

    pos = parse_dns(pos, header, packet, &dns);
    
}
