#include "main.h"
#include "protocols.h"

// Function declarations for tcp protocol handling.

#ifndef __DP_TCP
#define __DP_TCP

tcp_info * tcp_assemble(tcp_info *);
void tcp_print(tcp_info *);
void tcp_save_state(config *);
tcp_info * tcp_load_state(config *);
void tcp_parse(bpf_u_int32, struct pcap_pkthdr *, u_char *, ip_info *, 
               config *);
void tcp_expire(config *, const struct timeval *);

#endif
