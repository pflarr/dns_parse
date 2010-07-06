#ifndef __RTYPES_H__
#define __RTYPES_H__

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

typedef char * rr_data_parser(const u_char*, bpf_u_int32, u_short);

typedef struct rr_parser_container {
    u_short rtype;
    rr_data_parser * parser;
} rr_parser_container;

rr_parser_container * find_parser(u_short, u_short);

char * read_dns_name(u_char *, bpf_u_int32, bpf_u_int32); 

// Prototype all the rr parser functions here.
rr_data_parser A_1;
rr_data_parser unknown_rtype;

// Add them to the list of data parsers in rtypes.c.
rr_parser_container rr_parsers[];

// This is for handling rr's with errors or an unhandled rtype.
rr_parser_container default_rr_parser;

#endif
