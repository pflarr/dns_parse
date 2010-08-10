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
    const char * name;
    const char * doc;
    unsigned long long count;
} rr_parser_container;

rr_parser_container * find_parser(u_short, u_short);

char * read_dns_name(u_char *, bpf_u_int32, bpf_u_int32); 

rr_data_parser opts;
rr_data_parser escape;

// Add them to the list of data parsers in rtypes.c.
extern rr_parser_container rr_parsers[];

// This is for handling rr's with errors or an unhandled rtype.
rr_parser_container default_rr_parser;

void print_parsers();
void print_parser_usage();

#endif
