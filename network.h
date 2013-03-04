#include "main.h"
#include "protocols.h"

#ifndef __BP_NETWORK
#define __BP_NETWORK
bpf_u_int32 eth_parse(struct pcap_pkthdr *, u_char *, eth_info *);
bpf_u_int32 mpls_parse(bpf_u_int32, struct pcap_pkthdr *, 
                       u_char *, eth_info *);
bpf_u_int32 ipv4_parse(bpf_u_int32, struct pcap_pkthdr *, 
                       u_char **, ip_info *, config *);
bpf_u_int32 ipv6_parse(bpf_u_int32, struct pcap_pkthdr *,
                       u_char **, ip_info *, config *);
ip_fragment * ip_frag_add(ip_fragment *, config *);
void ip_frag_free(config *);
bpf_u_int32 udp_parse(bpf_u_int32, struct pcap_pkthdr *, u_char *, 
                      transport_info *, config *);
#endif
