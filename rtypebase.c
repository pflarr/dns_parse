#include <types.h>
#include <stdlib.h>

rr_data_parser * find_parser(u_short rtype) {

    extern rr_parsers;
    extern default_rr_parser;
    unsigned int i, pcount = sizeof(rr_parsers)/sizeof(rr_parser_container*);

    while (i < pcount) {
        if ( rr_parsers[i].rtype == rtype ) 
            return rr_parsers[i];
        i++;
    }

    return default_rr_parser;
}

void dns_rr_free(dns_rr * rr) {
    free(rr->name);
    free(rr->data);
    if (rr->next != NULL) dns_rr_free(rr->next);
    free(rr);
}
