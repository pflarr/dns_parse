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
struct rr_parser_container rr_parsers[] = {{1, 1, A},
                                           {0, 2, domain_name}, // NS
                                           {0, 6, soa},
                                           {0, 12, domain_name}, // PTR
                                           {0, 5, domain_name}, // CNAME
                                           {0, 15, mx},
                                           {0, 16, unknown_rtype}, // TEXT
                                           {0, 10, unknown_rtype}, // NULL
                                           {1, 33, srv}, 
                                           {1, 28, AAAA},
                                           {0, 48, dnskey},
                                           {0, 46, rrsig},
                                           {0, 47, nsec},
                                           {0, 43, ds}
                                          };

// This is used when a parser isn't defined for a given class, rtypes.
rr_parser_container default_rr_parser = {0, 0, unknown_rtype};

// Find the parser that corresponds to the given cls and rtype.
rr_parser_container * find_parser(u_short cls, u_short rtype) {

    extern rr_parser_container rr_parsers[];
    extern rr_parser_container default_rr_parser;
    unsigned int i=0, pcount = sizeof(rr_parsers)/sizeof(rr_parser_container);
    
    while (i < pcount) {
        rr_parser_container pc = rr_parsers[i];
        if ((pc.rtype == rtype || pc.rtype == 0) &&
            (pc.cls == cls || pc.cls == 0)) {
//            printf("Unknown class, rtype %d,%d\n", cls, rtype);
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

char * A(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 i,
         u_short rdlength, bpf_u_int32 plen) {
    char * data = (char *)malloc(sizeof(char)*16);

    if (rdlength != 4) {
        free(data);
        return mk_error("Bad A record", packet, pos, rdlength);
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
    char *buffer;
    const char * base_format = "size:%d,rcode:0x%02x%02x%02x%02x,%s";
    char *rdata = escape_data(packet, pos+6, pos + 6 + rdlength);

    buffer = malloc(sizeof(char) * (strlen(base_format) - 10 + 5 + 
                                    strlen(rdata) + 1)); 
    sprintf(buffer, base_format, payload_size, packet[2], packet[3],
                                 packet[4], packet[5], rdata);
    free(rdata);
    return buffer;
}

char * srv(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 id_pos,
                 u_short rdlength, bpf_u_int32 plen) {
    u_short priority = (packet[pos] << 8) + packet[pos+1];
    u_short weight = (packet[pos+2] << 8) + packet[pos+3];
    u_short port = (packet[pos+4] << 8) + packet[pos+5];
    char *target, *buffer;
    pos = pos + 6;
    // Don't read beyond the end of the rr.
    target = read_rr_name(packet, &pos, id_pos, pos+rdlength-6);
    
    buffer = malloc(sizeof(char) * ((3*5+1) + strlen(target)));
    sprintf(buffer, "%d,%d,%d %s", priority, weight, port, target);
    free(target);
    return buffer;
}


char * AAAA(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 id_pos,
                  u_short rdlength, bpf_u_int32 plen) {
    char *buffer;
    u_short ipv6[8];
    int i;

    if (rdlength != 16) { 
        return mk_error("Bad AAAA record", packet, pos, rdlength);
    }

    for (i=0; i < 8; i++) 
        ipv6[i] = (packet[pos+i*2] << 8) + packet[pos+i*2+1];
    buffer = malloc(sizeof(char) * (4*8 + 7 + 1));
    sprintf(buffer, "%x:%x:%x:%x:%x:%x:%x:%x", ipv6[0], ipv6[1], ipv6[2],
                                               ipv6[3], ipv6[4], ipv6[5],
                                               ipv6[6], ipv6[7]); 
    return buffer;
}

char * dnskey(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 id_pos,
                    u_short rdlength, bpf_u_int32 plen) {
    u_short flags = (packet[pos] << 8) + packet[pos+1];
    u_char proto = packet[pos+2];
    u_char algorithm = packet[pos+3];
    int i;
    char *buffer, *key;

    key = b64encode(packet, pos+4, rdlength-4);
    buffer = malloc(sizeof(char) * (1 + strlen(key) + 18));
    sprintf(buffer, "%d,%d,%d,%s", flags, proto, algorithm, key);
    free(key);
    return buffer;
}

char * rrsig(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 id_pos,
                   u_short rdlength, bpf_u_int32 plen) {
    bpf_u_int32 o_pos = pos;
    u_short tc = (packet[pos] << 8) + packet[pos+1];
    u_char alg = packet[pos+2];
    u_char labels = packet[pos+3];
    u_int ottl, sig_exp, sig_inc;
    u_short key_tag = (packet[pos+16] << 8) + packet[pos+17];
    char *signer, *signature, *buffer;
    pos = pos + 4;
    ottl = (packet[pos] << 24) + (packet[pos+1] << 16) + 
           (packet[pos+2] << 8) + packet[pos+3];
    pos = pos + 4;
    sig_exp = (packet[pos] << 24) + (packet[pos+1] << 16) + 
              (packet[pos+2] << 8) + packet[pos+3];
    pos = pos + 4; 
    sig_inc = (packet[pos] << 24) + (packet[pos+1] << 16) + 
              (packet[pos+2] << 8) + packet[pos+3];
    pos = pos + 6;
    signer = read_rr_name(packet, &pos, id_pos, o_pos+rdlength);
    signature = b64encode(packet, pos, o_pos+rdlength-pos);
    buffer = malloc(sizeof(char) * (2*5 + // 2 16 bit ints
                                    3*10 + // 3 32 bit ints
                                    2*3 + // 2 8 bit ints
                                    8 + // 8 separator chars
                                    strlen(signer) +
                                    strlen(signature) + 1));
    sprintf(buffer, "%d,%d,%d,%d,%d,%d,%d,%s,%s", tc, alg, labels, ottl, 
                    sig_exp, sig_inc, key_tag, signer, signature);
    free(signer);
    free(signature);
    return buffer;
}

char * nsec(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 id_pos,
                  u_short rdlength, bpf_u_int32 plen) {

    char *buffer, *domain, *bitmap;

    domain = read_rr_name(packet, &pos, id_pos, pos+rdlength);
    bitmap = escape_data(packet, pos, pos+rdlength);
    buffer = malloc(sizeof(char) * (strlen(domain)+strlen(bitmap)+2));
    sprintf(buffer, "%s,%s", domain, bitmap);
    free(domain);
    free(bitmap);
    return buffer;

}

char * ds(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 id_pos,                     u_short rdlength, bpf_u_int32 plen) {
    u_short key_tag = (packet[pos] << 8) + packet[pos+1];
    u_char alg = packet[pos+2];
    u_char dig_type = packet[pos+3];
    char * digest = b64encode(packet,pos+4,rdlength-4);
    char * buffer;

    buffer = malloc(sizeof(char) * (strlen(digest) + 15));
    sprintf(buffer,"%d,%d,%d,%s", key_tag, alg, dig_type, digest);
    free(digest);
    return buffer;
}

char * unknown_rtype(const u_char * packet, bpf_u_int32 pos, bpf_u_int32 i,
                     u_short rdlength, bpf_u_int32 plen) {
    return escape_data(packet, pos, pos + rdlength);
}
