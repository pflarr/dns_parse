#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

char * escape_data(const uint8_t * packet, uint32_t start, uint32_t end) { 
    int i,o;
    uint8_t c;
    unsigned int length=1;

    char * outstr;

    for (i=start; i<end; i++) {
        c = packet[i];
        if (c < 0x20 || c == 0x5c || c >= 0x7f) length += 4;
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

char * read_rr_name(const uint8_t * packet, uint32_t * packet_p, 
                    uint32_t id_pos, uint32_t len) {
    uint32_t i, next, pos=*packet_p;
    uint32_t end_pos = 0;
    uint32_t name_len=0;
    uint32_t steps = 0;
    char * name;

    // Scan through the name, one character at a time. We need to look at 
    // each character to look for values we can't print in order to allocate
    // extra space for escaping them.  'next' is the next position to look
    // for a compression jump or name end.
    // It's possible that there are endless loops in the name. Our protection
    // against this is to make sure we don't read more bytes in this process
    // than twice the length of the data.  Names that take that many steps to 
    // read in should be impossible.
    next = pos;
    while (pos < len && !(next == pos && packet[pos] == 0)
           && steps < len*2) {
        uint8_t c = packet[pos];
        steps++;
        if (next == pos) {
            // Handle message compression.  
            // If the length byte starts with the bits 11, then the rest of
            // this byte and the next form the offset from the dns proto start
            // to the start of the remainder of the name.
            if ((c & 0xc0) == 0xc0) {
                if (pos + 1 >= len) return 0;
                if (end_pos == 0) end_pos = pos + 1;
                pos = id_pos + ((c & 0x3f) << 8) + packet[pos+1];
                next = pos;
            } else {
                name_len++;
                pos++;
                next = next + c + 1; 
            }
        } else {
            if (c >= '!' && c <= 'z' && c != '\\') name_len++;
            else name_len += 4;
            pos++;
        }
    }
    if (end_pos == 0) end_pos = pos;

    // Due to the nature of DNS name compression, it's possible to get a
    // name that is infinitely long. Return an error in that case.
    // We use the len of the packet as the limit, because it shouldn't 
    // be possible for the name to be that long.
    if (steps >= 2*len || pos >= len) return NULL;

    name_len++;

    name = (char *)malloc(sizeof(char) * name_len);
    pos = *packet_p;

    //Now actually assemble the name.
    //We've already made sure that we don't exceed the packet length, so
    // we don't need to make those checks anymore.
    // Non-printable and whitespace characters are replaced with a question
    // mark. They shouldn't be allowed under any circumstances anyway.
    // Other non-allowed characters are kept as is, as they appear sometimes
    // regardless.
    // This shouldn't interfere with IDNA (international
    // domain names), as those are ascii encoded.
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
            uint8_t c = packet[pos];
            if (c >= '!' && c <= '~' && c != '\\') {
                name[i] = packet[pos];
                i++; pos++;
            } else {
                name[i] = '\\';
                name[i+1] = 'x';
                name[i+2] = c/16 + 0x30;
                name[i+3] = c%16 + 0x30;
                if (name[i+2] > 0x39) name[i+2] += 0x27;
                if (name[i+3] > 0x39) name[i+3] += 0x27;
                i+=4; 
                pos++;
            }
        }
    }
    name[i] = 0;

    *packet_p = end_pos + 1;

    return name;
}

static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char * b64encode(const uint8_t * data, uint32_t pos, uint16_t length) {
    char * out;
    uint32_t end_pos = pos + length;
    uint32_t op = 0;

    // We allocate a little extra here sometimes, but in this application
    // these strings are almost immediately de-allocated anyway.
    out = malloc(sizeof(char) * ((length/3 + 1)*4 + 1));

    while (pos + 2 < end_pos) {
        out[op] = cb64[ data[pos] >> 2 ];
        out[op+1] = cb64[ ((data[pos] & 0x3) << 4) | 
                          ((data[pos+1] & 0xf0) >> 4) ];
        out[op+2] = cb64[ ((data[pos+1] & 0xf) << 2) | 
                          ((data[pos+2] & 0xc0) >> 6) ];
        out[op+3] = cb64[ data[pos+2] & 0x3f ];

        op = op + 4;
        pos = pos + 3;
    }

    if ((end_pos - pos) == 2) {
        out[op] = cb64[ data[pos] >> 2 ];
        out[op+1] = cb64[ ((data[pos] & 0x3) << 4) | 
                          ((data[pos+1] & 0xf0) >> 4) ];
        out[op+2] = cb64[ ((data[pos+1] & 0xf) << 2) ];
        out[op+3] = '=';
        op = op + 4;
    } else if ((end_pos - pos) == 1) {
        out[op] = cb64[ data[pos] >> 2 ];
        out[op+1] = cb64[ ((data[pos] & 0x3) << 4) ];
        out[op+2] = out[op+3] = '=';
        op = op + 4;
    }
    out[op] = 0; 

    return out;
}

#ifdef __STRUTILS_TESTING__
int main() {

    uint8_t * ed_data = "  "
                    "\x00\x0f\x10\x1f\x5c\x7f" // 6
                    "abcdefghijklmnopqrstuvwxyz" // 26
                    "1234567890" // 10
                    "ZYXWVUTSRQPONMLKJIHGFEDCBA" // 26
                    "+_)(*&^%$#@!~`-=[]{}|;':<>?,./" // 30
                    "\\ \"" // 3, 101 total
                    "blahblahblah"; 
    char * s = escape_data(ed_data, 2, 103);
    char * result = "\\x00\\x0f\\x10\\x1f\\x5c\\x7fabcdefghijklmnopqrstuvwxyz1234567890ZYXWVUTSRQPONMLKJIHGFEDCBA+_)(*&^%$#@!~`-=[]{}|;':<>?,./\\x5c \"";

    uint8_t * name_data = "5junk\x03rat\x04\x7f\x00\xe3\\\x03gov\x00tenjunkchr"
                         "\x05hello\x03the\xc0\x01";
    const char * name_result = "hello.the.rat.\\x7f\\x00\\xe3\\x5c.gov";
    uint32_t pos;
    int i;
    uint8_t b64data[256];
    char * b64result;
    char * b64t1 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w==";
    char * b64t2 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/";
    char * b64t3 = "AgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8=";
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

    pos = 29;
    s = read_rr_name(name_data, &pos, 4, 41);

    if ((strcmp(s, name_result) == 0) && pos == 41) 
        printf("name parse test ok.\n");
    else {
        printf("pos: %d\n", pos);
        printf("name parse test failed: \n%s\n%s\n", s,name_result);
        for (i=0; i<35; i++)
            printf("%x, %x, %c, %c\n", s[i], name_result[i],
                                       s[i], name_result[i]);
    }

    free(s); 

    for (i=0; i<256; i++) b64data[i] = i;

    b64result = b64encode(b64data,0,256);
    if (strcmp(b64result, b64t1)) 
        printf("b64 test failed.\n%s\n%s\n", b64result, b64t1);
    else printf("b64 test1 passed\n");
    free(b64result); 
    b64result = b64encode(b64data,1,255);
    if (strcmp(b64result, b64t2)) 
        printf("b64 test failed.\n%s\n%s\n", b64result, b64t2);
    else printf("b64 test2 passed\n");
    free(b64result); 
    b64result = b64encode(b64data,2,254);
    if (strcmp(b64result, b64t3)) 
        printf("b64 test failed.\n%s\n%s\n", b64result, b64t3);
    else printf("b64 test3 passed\n");
    return 0;
}
#endif
