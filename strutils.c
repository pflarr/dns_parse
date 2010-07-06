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

#ifdef __STRUTILS_TESTING__
int main() {

    u_char * data = "  "
                    "\x00\x0f\x10\x1f\x5c\x7f" // 6
                    "abcdefghijklmnopqrstuvwxyz" // 26
                    "1234567890" // 10
                    "ZYXWVUTSRQPONMLKJIHGFEDCBA" // 26
                    "+_)(*&^%$#@!~`-=[]{}|;':<>?,./" // 30
                    "\\ \"" // 3, 101 total
                    "blahblahblah"; 
    char * s = escape_data(data, 2, 103);
    char * result = "\\x00\\x0f\\x10\\x1f\\x5c\\x7fabcdefghijklmnopqrstuvwxyz1234567890ZYXWVUTSRQPONMLKJIHGFEDCBA+_)(*&^%$#@!~`-=[]{}|;':<>?,./\\x5c \"";
    if (strcmp(s,result) == 0) printf("Test ok\n");
    else {
        printf("Test Failed\n");
        int i = 0;
        char n = s[0], r=result[0];
        while (n == r) {
            printf("%c, %c, %d\n", n, r, n == r);
            i++;
            n = s[i]; r=result[i];
        }
        printf("%c, %c, %d\n", n, r, n == r);
    }

    return 1;
}
#endif
    
