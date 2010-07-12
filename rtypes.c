#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rtypes.h"
#include "strutils.h"

// Add parser functions here, they should be prototyped in rtypes.h and
// then defined below.
// Some of the rtypes below use the unknown_rtype parser.  This isn't
// because we don't know how to parse them, it's simply because that's
// the right parser for them anyway.
struct rr_parser_container rr_parsers[] = {{1, 1, A_1},
                                           {0, 2, domain_name}, // NS
                                           {0, 6, soa},
                                           {0, 41, opts},
                                           {0, 12, domain_name}, // PTR
                                           {0, 5, domain_name}, // CNAME
                                           {0, 15, mx},
                                           {0, 16, unknown_rtype}, // TEXT
                                           {0, 10, unknown_rtype} // NULL
                                          };

// This is used when a parser isn't defined for a given class, rtypes.
rr_parser_container default_rr_parser = {0, unknown_rtype};

// Find the parser that corresponds to the given cls and rtype.
rr_parser_container * find_parser(u_short cls, u_short rtype) {

    extern rr_parser_container rr_parsers[];
    extern rr_parser_container default_rr_parser;
    unsigned int i=0, pcount = sizeof(rr_parsers)/sizeof(rr_parser_container);
    
    while (i < pcount) {
        rr_parser_container pc = rr_parsers[i];
        if ((pc.rtype == rtype || pc.rtype == 0) &&
            (pc.cls == cls || pc.cls == 0)) {
            printf("Unknown class, rtype %d,%d\n", cls, rtype);
            return &rr_parsers[i];
        }
        i++;
    }

    printf("Unknown class, rtype %d,%d\n", cls, rtype);
    return &default_rr_parser;
}

char * mk_error(const char * msg, const u_char * packet, bpf_u_int32 pos,
                u_short rdlength) {
    char * tmp = escape_data(packet, pos, pos+rdlength);
    size_t len = strlen(tmp) + strlen(msg);
    char * buffer = malloc(sizeof(char)*len + 1);
    sprintf(buffer, "%s - %s", msg, tmp);
    free(tmp);
    return buffer;
}

char * A_1(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 i,
           u_short rdlength, bpf_u_int32 plen) {
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

char * domain_name(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 id_pos,
                   u_short rdlength, bpf_u_int32 plen) {
    // We use a dummy position variable because we already know the length of
    // the data and we don't need read_rr_name to tell us.
    bpf_u_int32 dummy_pos = pos;
    // Fake the end of packet length
    return read_rr_name(packet, &dummy_pos, id_pos, plen);
}

char * soa(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 id_pos,
                   u_short rdlength, bpf_u_int32 plen) {
    char * mname;
    char * rname;
    char * buffer;
    bpf_u_int32 serial, refresh, retry, expire, minimum;
    const char * format = "mname: %s, rname: %s, serial: %d, "
                          "refresh: %d, retry: %d, expire: %d, min: %d";

    mname = read_rr_name(packet, &pos, id_pos, plen);
    if (mname == NULL) return mk_error("Bad SOA", packet, pos, rdlength);
    rname = read_rr_name(packet, &pos, id_pos, plen);
    if (rname == NULL) return mk_error("Bad SOA", packet, pos, rdlength);

    serial = (packet[pos] << 8) + packet[pos+1];
    refresh = (packet[pos+2] << 8) + packet[pos+3];
    retry = (packet[pos+4] << 8) + packet[pos+5];
    expire = (packet[pos+6] << 8) + packet[pos+7];
    minimum = (packet[pos+8] << 8) + packet[pos+9];
    
    // The 5 tens are for the max of ten digits for the numeric fields.
    // The format string will lose 14 chrs of format marks.
    // The +1 is for the terminating null.
    buffer = malloc(sizeof(char) * (strlen(format) + strlen(mname) + 
                                    strlen(rname) + 10*5 - 14 + 1));
    sprintf(buffer, format, mname, rname, serial, refresh, retry, expire,
            minimum);
    free(mname);
    free(rname);
    return buffer;
}

char * mx(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 id_pos,
                   u_short rdlength, bpf_u_int32 plen) {

    u_short pref = (packet[pos] << 8) + packet[pos+1];
    char * name;
    char * buffer;

    pos = pos + 2;
    name = read_rr_name(packet, &pos, id_pos, plen);

    buffer = malloc(sizeof(char)*(20 + strlen(name)));
    sprintf(buffer, "preference: %d, %s", pref, name);
    free(name);
    return buffer;
}

char * opts(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 id_pos,
                  u_short rdlength, bpf_u_int32 plen) {
    u_short payload_size = (packet[pos] << 8) + packet[pos+1];
    char *buffer, *last;
    const char * base_format = "edns size: %d, rcode: 0x%x%x%x%x, ";
    bpf_u_int32 rdata_start = pos + 6;

    pos = pos + 6;

    last = malloc(sizeof(char) * (strlen(base_format) - 2 + 5)); 
    sprintf(last, base_format, payload_size, 
            packet[3],packet[4],packet[5],packet[6]);

    while ((pos + 4) < (rdata_start + rdlength)) {
            
    }
}



char * unknown_rtype(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 i,
                     u_short rdlength, bpf_u_int32 plen) {
    return escape_data(packet, pos, pos + rdlength);
}
