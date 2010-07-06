#ifndef __DNS_STR_UTILS__
#define __DNS_STR_UTILS__

// Encodes the data into plaintext (minus newlines and delimiters).  Escaped
// characters are in the format \x33 (an ! in this case).  The escaped 
// characters are:
//  All characters < \x20
//  Backslash (\x5c)
//  All characters >= \x7f
// Arguments (packet, start, end):
//  packet - The u_char array of the whole packet.
//  start - the position of the first character in the data.
//  end - the position + 1 of the last character in the data.
char * escape_data(const u_char *, bpf_u_int32, bpf_u_int32);

#endif
