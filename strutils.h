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

// Read a reservation record style name, dealing with any compression.
// A newly allocated string of the read name with length bytes 
// converted to periods is placed in the char * argument. 
// If there was an error reading the name, 0 is returned, otherwise
// the new read position is returned.
// Args (packet, pos, id_pos, len, name)
//  packet - The u_char array of the whole packet.
//  pos - the start of the rr
//  id_pos - the start of the dns packet (id field)
//  len - the length of the whole packet
//  name - We will return read name via this pointer.
char * read_rr_name(const u_char *, bpf_u_int32 *, bpf_u_int32, bpf_u_int32);

#endif
