//#define __STRUTILS_TESTING__

#ifdef __STRUTILS_TESTING__
#include <stdio.h>
#include <string.h>
#endif

#include <pcap.h>
#include <stdlib.h>

char * escape_data(const u_char * packet, bpf_u_int32 start, bpf_u_int32 end) { 
    int i,o;
    u_char c, upper, lower;
    unsigned int length=1;

    char * outstr;

    for (i=start; i<end; i++) {
        c = packet[i];
        if (c < 0x20 || c == 0x5c || c >= 0x75) length += 4;
        else length += 1;
    }

    outstr = (char *)malloc(sizeof(char)*length);
    // If the malloc failed then fail.
    if (outstr == 0) return (char *)0;

    o=0;
    for (i=start; i<end; i++) {
        c = packet[i];
        if (c < 0x20 || c == 0x5c || c >= 0x7f) {
            outstr[o] = '\\';
            outstr[o+1] = 'x';
            outstr[o+2] = c/16 + 0x30;
            outstr[o+3] = c%16 + 0x30;
            if (outstr[o+2] > 0x39) outstr[o+2] += 0x27;
            if (outstr[o+3] > 0x39) outstr[o+3] += 0x27;
            o += 4;
        } else {
            outstr[o] = c;
            o++;
        }
    }
    outstr[o] = 0;
    return outstr;
}

char * read_rr_name(const u_char * packet, bpf_u_int32 * packet_p, 
                    bpf_u_int32 id_pos, bpf_u_int32 len) {
    
    bpf_u_int32 i, next, pos=*packet_p;
    bpf_u_int32 end_pos = 0;
    bpf_u_int32 name_len=0;
    char * name;


    while (packet[pos] != 0 && pos < len) {
        // Handle message compression.  
        // If the length byte starts with the bits 11, then the rest of
        // this byte and the next form the offset from the dns proto start
        // to the start of the remainder of the name.
        if ((packet[pos] & 0xc0) == 0xc0) {
            // Check for exceeding the packet length.
            if (pos + 1 >= len) return 0;
            if (end_pos == 0) end_pos = pos + 1;
            pos = id_pos + ((packet[pos] & 0x3f) << 8) + packet[pos+1];
        } else {
            name_len += packet[pos]+1;
            pos += packet[pos]+1;
        }
    }
    if (end_pos == 0) end_pos = pos;

    if (pos >= len) return 0;

    name = (char *)malloc(sizeof(char) * name_len);
    pos = *packet_p;

    //Now actually assemble the name.
    //We've already made sure that we don't exceed the packet length, so
    // we don't need to make those checks anymore.
    // Next is where to next check for a length or end of packet.
    next = pos;
    i = 0;
    while (next != pos || packet[pos] != 0) {
        if (pos == next) {
            if ((packet[pos] & 0xc0) == 0xc0) {
                pos = id_pos + ((packet[pos] & 0x3f) << 8) + packet[pos+1];
                next = pos;
            } else {
                // Add a period except for the first time.
                if (i != 0) name[i++] = '.';
                next = pos + packet[pos] + 1;
                pos++;
            }
        } else {
            name[i] = packet[pos];
            i++; pos++;
        }
    }
    name[i] = 0;

    *packet_p = end_pos + 1;
    return name;
}
#ifdef __STRUTILS_TESTING__
int main() {

    u_char * ed_data = "  "
                    "\x00\x0f\x10\x1f\x5c\x7f" // 6
                    "abcdefghijklmnopqrstuvwxyz" // 26
                    "1234567890" // 10
                    "ZYXWVUTSRQPONMLKJIHGFEDCBA" // 26
                    "+_)(*&^%$#@!~`-=[]{}|;':<>?,./" // 30
                    "\\ \"" // 3, 101 total
                    "blahblahblah"; 
    char * s = escape_data(ed_data, 2, 103);
    char * result = "\\x00\\x0f\\x10\\x1f\\x5c\\x7fabcdefghijklmnopqrstuvwxyz1234567890ZYXWVUTSRQPONMLKJIHGFEDCBA+_)(*&^%$#@!~`-=[]{}|;':<>?,./\\x5c \"";
    
    u_char * name_data = "5junk\x03rat\x03gov\x00tenjunkchr"
                         "\x05hello\x03the\xc0\x01";
    const char * name_result = "hello.the.rat.gov";
    bpf_u_int32 pos;

    if (strcmp(s,result) == 0) printf("escape_data Test ok\n");
    else {
        printf("escape_data Test Failed\n");
        int i = 0;
        char n = s[0], r=result[0];
        while (n == r) {
            printf("%c, %c, %d\n", n, r, n == r);
            i++;
            n = s[i]; r=result[i];
        }
        printf("%c, %c, %d\n", n, r, n == r);
    }

    free(s);
    s = NULL;

    pos = 24;
    s = read_rr_name(name_data, &pos, 4, 40);

    if ((strcmp(s, name_result) == 0) && pos == 36) 
        printf("name parse test ok.\n");
    else {
        int i;
        printf("name parse test failed.\n");
        for (i=0; i<17; i++)
            printf("%d, %d\n", s[i], name_result[i]);
    }

    free(s); 
    return 0;
}
#endif
    
