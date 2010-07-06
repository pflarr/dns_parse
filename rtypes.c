#include <stdio.h>
#include <stdlib.h>
#include "rtypes.h"
#include "strutils.h"

// Add parser functions here, they should be prototyped in rtypes.h and
// then defined below.
struct rr_parser_container rr_parsers[] = {{1, A_1}};

// This is used when a parser isn't defined for a given class, rtypes.
rr_parser_container default_rr_parser = {0, unknown_rtype};

// Find the parser that corresponds to the given cls and rtype.
rr_parser_container * find_parser(u_short cls, u_short rtype) {

    extern rr_parser_container rr_parsers[];
    extern rr_parser_container default_rr_parser;
    unsigned int i, pcount = sizeof(rr_parsers)/sizeof(rr_parser_container*);

    if ( cls != 1 ) return &default_rr_parser;

    while (i < pcount) {
        if ( rr_parsers[i].rtype == rtype ) 
            return &rr_parsers[i];
        i++;
    }

    return &default_rr_parser;
}

char * A_1(const u_char * packet, bpf_u_int32 pos, u_short rdlength) {
    char * data = (char *)malloc(sizeof(char)*16);

    if (rdlength != 4) {
        fprintf(stderr, "Bad A record\n");
        free(data);
        return NULL;
    }
    
    sprintf(data, "%d.%d.%d.%d", packet[pos], packet[pos+1],
                                 packet[pos+2], packet[pos+3]);

    return data;
}

char * unknown_rtype(const u_char * packet, bpf_u_int32 pos, u_short rdlength){
    return escape_data(packet, pos, pos + rdlength);
}
