#include "rtypes.h"
#include "types.h"
#include <stdlib.h>

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

void dns_rr_free(dns_rr * rr) {
    if (rr->name != NULL) free(rr->name);
    if (rr->data != NULL) free(rr->data);
    if (rr->next != NULL) dns_rr_free(rr->next);
    free(rr);
}
