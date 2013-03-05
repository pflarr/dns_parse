#include "dns_parse.h"
#include "network.h"

// Function declarations for tcp protocol handling.

#ifndef __DP_TCP
#define __DP_TCP

// TCP header information. Also contains pointers used to connect to this
// to other TCP streams, and to connect this packet to other packets in
// it's stream.
typedef struct tcp_info {
    struct timeval ts;
    ip_addr src;
    ip_addr dst;
    uint16_t srcport;
    uint16_t dstport;
    uint32_t sequence;
    uint32_t ack_num;
    // The length of the data portion.
    uint32_t len;
    uint8_t syn;
    uint8_t ack;
    uint8_t fin;
    uint8_t rst;
    uint8_t * data;
    // The next item in the list of tcp sessions.
    struct tcp_info * next_sess;
    // These are for connecting all the packets in a session. The session
    // pointers above will always point to the most recent packet.
    // next_pkt and prev_pkt make chronological sense (next_pkt is always 
    // more recent, and prev_pkt is less), we just hold the chain by the tail.
    struct tcp_info * next_pkt;
    struct tcp_info * prev_pkt;
} tcp_info;

// Print the TCP header information. Used for debugging.
void tcp_print(tcp_info *);
// Save all the current unresolved TCP streams to file.
void tcp_save_state(config *);
// Load TCP streams saved by tcp_save_state.
tcp_info * tcp_load_state(config *);
// Parse a TCP packet, and attach the data to a TCP stream.
void tcp_parse(uint32_t, struct pcap_pkthdr *, uint8_t *, ip_info *, 
               config *);
// Assemble the TCP packets in the list with it's head at the given
// tcp_info struct.
tcp_info * tcp_assemble(tcp_info *);
// Expire TCP streams based on the given timeval and the compile time defined
// expiration time limit. The age of a stream is based on the last packet 
// it received. A timeval of NULL will expire all streams.
// Expired streams are put through tcp reassembly.
// Each reassembled stream is then put through dns parsing.
// Parsed DNS data is then output.
void tcp_expire(config *, const struct timeval *);

#endif
