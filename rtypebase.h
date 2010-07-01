#ifndef __RTYPE_BASE_H__
#define __RTYPE_BASE_H__

#include <pcap.h>
#include "types.h"

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

void dns_rr_free(dns_rr *);

typedef char * rr_data_parser(u_char*, bpf_u_int32, u_short);

typedef struct rr_parser_container {
    u_short rtype;
    rr_data_parser * parser;
} rr_parser_container;

rr_parser_container * find_parser(u_short, u_short);

char * read_dns_name(u_char *, bpf_u_int32, bpf_u_int32); 

char * escape_data(u_char *, bpf_u_int32, bpf_u_int32);

#endif
