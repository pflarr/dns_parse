#ifndef __RTYPES_H__
#define __RTYPES_H__

#include <pcap.h>
#include <stdint.h>

typedef char * rr_data_parser(const uint8_t*, uint32_t, uint32_t, 
                              uint16_t, uint32_t);

typedef struct {
    uint16_t cls;
    uint16_t rtype;
    rr_data_parser * parser;
    const char * name;
    const char * doc;
    unsigned long long count;
} rr_parser_container;

rr_parser_container * find_parser(uint16_t, uint16_t);

char * read_dns_name(uint8_t *, uint32_t, uint32_t); 

rr_data_parser opts;
rr_data_parser escape;

// Add them to the list of data parsers in rtypes.c.
extern rr_parser_container rr_parsers[];

// This is for handling rr's with errors or an unhandled rtype.
rr_parser_container default_rr_parser;

void print_parsers();
void print_parser_usage();

#endif
