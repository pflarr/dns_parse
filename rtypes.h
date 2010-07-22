#ifndef __RTYPES_H__
#define __RTYPES_H__

#include <pcap.h>
#include "types.h"

typedef char * rr_data_parser(const u_char*, bpf_u_int32, bpf_u_int32, 
                              u_short, bpf_u_int32);

typedef struct rr_parser_container {
    u_short cls;
    u_short rtype;
    rr_data_parser * parser;
} rr_parser_container;

rr_parser_container * find_parser(u_short, u_short);

char * read_dns_name(u_char *, bpf_u_int32, bpf_u_int32); 

// Prototype all the rr parser functions here.
rr_data_parser A;
rr_data_parser domain_name;
rr_data_parser mx;
rr_data_parser soa;
rr_data_parser opts;
rr_data_parser srv;
rr_data_parser AAAA;
rr_data_parser dnskey;
rr_data_parser rrsig;
rr_data_parser nsec;
rr_data_parser ds;

rr_data_parser unknown_rtype;

// Add them to the list of data parsers in rtypes.c.
extern rr_parser_container rr_parsers[];

// This is for handling rr's with errors or an unhandled rtype.
rr_parser_container default_rr_parser;

#endif
