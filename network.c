#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "network.h"

// Parse the ethernet headers, and return the payload position (0 on error).
uint32_t eth_parse(struct pcap_pkthdr *header, uint8_t *packet,
                   eth_info * eth, config * conf) {
    uint32_t pos = 0;

    if (header->len < 14) {
        fprintf(stderr, "Truncated Packet(eth)\n");
        return 0;
    }

    while (pos < 6) {
        eth->dstmac[pos] = packet[pos];
        eth->srcmac[pos] = packet[pos+6];
        pos++;
    }
    pos = pos + 6;
   
    // Skip the extra 2 byte field inserted in "Linux Cooked" captures.
    if (conf->datalink == DLT_LINUX_SLL) {
        pos = pos + 2;
    }

    // Skip VLAN tagging 
    if (packet[pos] == 0x81 && packet[pos+1] == 0) pos = pos + 4;

    eth->ethtype = (packet[pos] << 8) + packet[pos+1];
    pos = pos + 2;

    SHOW_RAW(
        printf("\neth ");
        print_packet(header->len, packet, 0, pos, 18);
    )
    VERBOSE(
        printf("dstmac: %02x:%02x:%02x:%02x:%02x:%02x, "
               "srcmac: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->dstmac[0],eth->dstmac[1],eth->dstmac[2],
               eth->dstmac[3],eth->dstmac[4],eth->dstmac[5],
               eth->srcmac[0],eth->srcmac[1],eth->srcmac[2],
               eth->srcmac[3],eth->srcmac[4],eth->srcmac[5]);
    )
    return pos;
}

// Parse MPLS. We don't care about the data in these headers, all we have
// to do is continue parsing them until the 'bottom of stack' flag is set.
uint32_t mpls_parse(uint32_t pos, struct pcap_pkthdr *header,
                    uint8_t *packet, eth_info * eth) {
    // Bottom of stack flag.
    uint8_t bos;
    do {
        VERBOSE(printf("MPLS Layer.\n");)
        // Deal with truncated MPLS.
        if (header->len < (pos + 4)) {
            fprintf(stderr, "Truncated Packet(mpls)\n");
            return 0;
        }

        bos = packet[pos + 2] & 0x01;
        pos += 4;
        DBG(printf("MPLS layer. \n");)
    } while (bos == 0);

    if (header->len < pos) {
        fprintf(stderr, "Truncated Packet(post mpls)\n");
        return 0;
    }


    // 'Guess' the next protocol. This can result in false positives, but
    // generally not.
    uint8_t ip_ver = packet[pos] >> 4;
    switch (ip_ver) {
        case IPv4:
            eth->ethtype = 0x0800; break;
        case IPv6:
            eth->ethtype = 0x86DD; break;
        default:
            eth->ethtype = 0;
    }

    return pos;
}

// Parse the IPv4 header. May point p_packet to a new packet data array,
// which means zero is a valid return value. Sets p_packet to NULL on error.
// See RFC791
uint32_t ipv4_parse(uint32_t pos, struct pcap_pkthdr *header, 
                    uint8_t ** p_packet, ip_info * ip, config * conf) {

    uint32_t h_len;
    ip_fragment * frag = NULL;
    uint8_t frag_mf;
    uint16_t frag_offset;

    // For convenience and code consistency, dereference the packet **.
    uint8_t * packet = *p_packet;

    if (header-> len - pos < 20) {
        fprintf(stderr, "Truncated Packet(ipv4)\n");
        *p_packet = NULL;
        return 0;
    }

    h_len = packet[pos] & 0x0f;
    ip->length = (packet[pos+2] << 8) + packet[pos+3] - h_len*4;
    ip->proto = packet[pos+9];

    IPv4_MOVE(ip->src, packet + pos + 12);
    IPv4_MOVE(ip->dst, packet + pos + 16);

    // Set if NOT the last fragment.
    frag_mf = (packet[pos+6] & 0x20) >> 5;
    // Offset for this data in the fragment.
    frag_offset = ((packet[pos+6] & 0x1f) << 11) + (packet[pos+7] << 3);

    SHOW_RAW(
        printf("\nipv4\n");
        print_packet(header->len, packet, pos, pos + 4*h_len, 4);
    )
    VERBOSE(
        printf("version: %d, length: %d, proto: %d\n", 
                IPv4, ip->length, ip->proto);
        printf("src ip: %s, ", iptostr(&ip->src));
        printf("dst ip: %s\n", iptostr(&ip->dst));
    )

    if (frag_mf == 1 || frag_offset != 0) {
        VERBOSE(printf("Fragmented IPv4, offset: %u, mf:%u\n", frag_offset,
                                                               frag_mf);)
        frag = malloc(sizeof(ip_fragment));
        frag->start = frag_offset;
        // We don't try to deal with endianness here, since it 
        // won't matter as long as we're consistent.
        frag->islast = !frag_mf;
        frag->id = *((uint16_t *)(packet + pos + 4));
        frag->src = ip->src;
        frag->dst = ip->dst;
        frag->end = frag->start + ip->length;
        frag->data = malloc(sizeof(uint8_t) * ip->length);
        frag->next = frag->child = NULL;
        memcpy(frag->data, packet + pos + 4*h_len, ip->length);
        // Add the fragment to the list.
        // If this completed the packet, it is returned.
        frag = ip_frag_add(frag, conf); 
        if (frag != NULL) {
            // Update the IP info on the reassembled data.
            header->len = ip->length = frag->end - frag->start;
            *p_packet = frag->data;
            free(frag);
            return 0;
        }
        // Signals that there is no more work to do on this packet.
        *p_packet = NULL;
        return 0;
    } 

    // move the position up past the options section.
    return pos + 4*h_len;

}

// Parse the IPv6 header. May point p_packet to a new packet data array,
// which means zero is a valid return value. Sets p_packet to NULL on error.
// See RFC2460
uint32_t ipv6_parse(uint32_t pos, struct pcap_pkthdr *header,
                    uint8_t ** p_packet, ip_info * ip, config * conf) {

    // For convenience and code consistency, dereference the packet **.
    uint8_t * packet = *p_packet;

    // In case the IP packet is a fragment.
    ip_fragment * frag = NULL;
    uint32_t header_len = 0;

    if (header->len < (pos + 40)) {
        fprintf(stderr, "Truncated Packet(ipv6)\n");
        *p_packet=NULL; return 0;
    }
    ip->length = (packet[pos+4] << 8) + packet[pos+5];
    IPv6_MOVE(ip->src, packet + pos + 8);
    IPv6_MOVE(ip->dst, packet + pos + 24);

    // Jumbo grams will have a length of zero. We'll choose to ignore those,
    // and any other zero length packets.
    if (ip->length == 0) {
        fprintf(stderr, "Zero Length IP packet, possible Jumbo Payload.\n");
        *p_packet=NULL; return 0;
    }

    uint8_t next_hdr = packet[pos+6];
    VERBOSE(print_packet(header->len, packet, pos, pos+40, 4);)
    VERBOSE(printf("IPv6 src: %s, ", iptostr(&ip->src));)
    VERBOSE(printf("IPv6 dst: %s\n", iptostr(&ip->dst));)
    pos += 40;
   
    // We pretty much have no choice but to parse all extended sections,
    // since there is nothing to tell where the actual data is.
    uint8_t done = 0;
    while (done == 0) {
        VERBOSE(printf("IPv6, next header: %u\n", next_hdr);)
        switch (next_hdr) {
            // Handle hop-by-hop, dest, and routing options.
            // Yay for consistent layouts.
            case IPPROTO_HOPOPTS:
            case IPPROTO_DSTOPTS:
            case IPPROTO_ROUTING:
                if (header->len < (pos + 16)) {
                    fprintf(stderr, "Truncated Packet(ipv6)\n");
                    *p_packet = NULL; return 0;
                }
                next_hdr = packet[pos];
                // The headers are 16 bytes longer.
                header_len += 16;
                pos += packet[pos+1] + 1;
                break;
            case 51: // Authentication Header. See RFC4302
                if (header->len < (pos + 2)) {
                    fprintf(stderr, "Truncated Packet(ipv6)\n");
                    *p_packet = NULL; return 0;
                } 
                next_hdr = packet[pos];
                header_len += (packet[pos+1] + 2) * 4;
                pos += (packet[pos+1] + 2) * 4;
                if (header->len < pos) {
                    fprintf(stderr, "Truncated Packet(ipv6)\n");
                    *p_packet = NULL; return 0;
                } 
                break;
            case 50: // ESP Protocol. See RFC4303.
                // We don't support ESP.
                fprintf(stderr, "Unsupported protocol: IPv6 ESP.\n");
                if (frag != NULL) free(frag);
                *p_packet = NULL; return 0;
            case 135: // IPv6 Mobility See RFC 6275
                if (header->len < (pos + 2)) {
                    fprintf(stderr, "Truncated Packet(ipv6)\n");
                    *p_packet = NULL; return 0;
                }  
                next_hdr = packet[pos];
                header_len += packet[pos+1] * 8;
                pos += packet[pos+1] * 8;
                if (header->len < pos) {
                    fprintf(stderr, "Truncated Packet(ipv6)\n");
                    *p_packet = NULL; return 0;
                } 
                break;
            case IPPROTO_FRAGMENT:
                // IP fragment.
                next_hdr = packet[pos];
                frag = malloc(sizeof(ip_fragment));
                // Get the offset of the data for this fragment.
                frag->start = (packet[pos+2] << 8) + (packet[pos+3] & 0xf4);
                frag->islast = !(packet[pos+3] & 0x01);
                // We don't try to deal with endianness here, since it 
                // won't matter as long as we're consistent.
                frag->id = *(uint32_t *)(packet+pos+4);
                // The headers are 8 bytes longer.
                header_len += 8;
                pos += 8;
                break;
            case TCP:
            case UDP:
                done = 1; 
                break;
            default:
                fprintf(stderr, "Unsupported IPv6 proto(%u).\n", next_hdr);
                *p_packet = NULL; return 0;
        }
    }

    // check for int overflow
    if (header_len > ip->length) {
      fprintf(stderr, "Malformed packet(ipv6)\n");
      *p_packet = NULL;
      return 0;
    }

    ip->proto = next_hdr;
    ip->length = ip->length - header_len;

    // Handle fragments.
    if (frag != NULL) {
        frag->src = ip->src;
        frag->dst = ip->dst;
        frag->end = frag->start + ip->length;
        frag->next = frag->child = NULL;
        frag->data = malloc(sizeof(uint8_t) * ip->length);
        VERBOSE(printf("IPv6 fragment. offset: %d, m:%u\n", frag->start,
                                                            frag->islast);)
        memcpy(frag->data, packet+pos, ip->length);
        // Add the fragment to the list.
        // If this completed the packet, it is returned.
        frag = ip_frag_add(frag, conf); 
        if (frag != NULL) {
            header->len = ip->length = frag->end - frag->start;
            *p_packet = frag->data;
            free(frag);
            return 0;
        }
        // Signals that there is no more work to do on this packet.
        *p_packet = NULL;
        return 0;
    } else {
        return pos;
    }

}

// Add this ip fragment to the our list of fragments. If we complete
// a fragmented packet, return it. 
// Limitations - Duplicate packets may end up in the list of fragments.
//             - We aren't going to expire fragments, and we aren't going
//                to save/load them like with TCP streams either. This may
//                mean lost data.
ip_fragment * ip_frag_add(ip_fragment * this, config * conf) {
    ip_fragment ** curr = &(conf->ip_fragment_head);
    ip_fragment ** found = NULL;

    DBG(printf("Adding fragment at %p\n", this);)

    // Find the matching fragment list.
    while (*curr != NULL) {
        if ((*curr)->id == this->id && 
            IP_CMP((*curr)->src, this->src) &&
            IP_CMP((*curr)->dst, this->dst)) {
            found = curr;
            DBG(printf("Match found. %p\n", *found);)
            break;
        }
        curr = &(*curr)->next;
    }

    // At this point curr will be the head of our matched chain of fragments, 
    // and found will be the same. We'll use found as our pointer into this
    // chain, and curr to remember where it starts.
    // 'found' could also be NULL, meaning no match was found.

    // If there wasn't a matching list, then we're done.
    if (found == NULL) {
        DBG(printf("No matching fragments.\n");)
        this->next = conf->ip_fragment_head;
        conf->ip_fragment_head = this;
        return NULL;
    }

    while (*found != NULL) {
        DBG(printf("*found: %u-%u, this: %u-%u\n",
                   (*found)->start, (*found)->end,
                   this->start, this->end);)
        if ((*found)->start >= this->end) {
            DBG(printf("It goes in front of %p\n", *found);)
            // It goes before, so put it there.
            this->child = *found;
            this->next = (*found)->next;
            *found = this;
            break;
        } else if ((*found)->child == NULL && 
                    (*found)->end <= this->start) {
            DBG(printf("It goes at the end. %p\n", *found);)
           // We've reached the end of the line, and that's where it
            // goes, so put it there.
            (*found)->child = this;
            break;
        }
        DBG(printf("What: %p\n", *found);)
        found = &((*found)->child);
    }
    DBG(printf("What: %p\n", *found);)

    // We found no place for the fragment, which means it's a duplicate
    // (or the chain is screwed up...)
    if (*found == NULL) {
        DBG(printf("No place for fragment: %p\n", *found);)
        free(this);
        return NULL;
    }

    // Now we try to collapse the list.
    found = curr;
    while ((*found != NULL) && (*found)->child != NULL) {
        ip_fragment * child = (*found)->child;
        if ((*found)->end == child->start) {
            DBG(printf("Merging frag at offset %u-%u with %u-%u\n", 
                        (*found)->start, (*found)->end,
                        child->start, child->end);)
            uint32_t child_len = child->end - child->start;
            uint32_t fnd_len = (*found)->end - (*found)->start;
            uint8_t * buff = malloc(sizeof(uint8_t) * (fnd_len + child_len));
            memcpy(buff, (*found)->data, fnd_len);
            memcpy(buff + fnd_len, child->data, child_len);
            (*found)->end = (*found)->end + child_len;
            (*found)->islast = child->islast;
            (*found)->child = child->child;
            // Free the old data and the child, and make the combined buffer
            // the new data for the merged fragment.
            free((*found)->data);
            free(child->data);
            free(child);
            (*found)->data = buff;
        } else {
            found = &(*found)->child;
        }
    }

    DBG(printf("*curr, start: %u, end: %u, islast: %u\n", 
                (*curr)->start, (*curr)->end, (*curr)->islast);)
    // Check to see if we completely collapsed it.
    // *curr is the pointer to the first fragment.
    if ((*curr)->islast != 0) {
        ip_fragment * ret = *curr;
        // Remove this from the fragment list.
        *curr = (*curr)->next;
        DBG(printf("Returning reassembled fragments.\n");)
        return ret;
    }
    // This is what happens when we don't complete a packet.
    return NULL;
}

// Free the lists of IP fragments.
void ip_frag_free(config * conf) {
    ip_fragment * curr;
    ip_fragment * child;

    while (conf->ip_fragment_head != NULL) {
        curr = conf->ip_fragment_head;
        conf->ip_fragment_head = curr->next;
        while (curr != NULL) {
            child = curr->child;
            free(curr->data);
            free(curr);
            curr = child;
        }
    }
}

// Parse the udp headers.
uint32_t udp_parse(uint32_t pos, struct pcap_pkthdr *header, 
                   uint8_t *packet, transport_info * udp, 
                   config * conf) {
    if (header->len - pos < 8) {
        fprintf(stderr, "Truncated Packet(udp)\n");
        return 0;
    }

    udp->srcport = (packet[pos] << 8) + packet[pos+1];
    udp->dstport = (packet[pos+2] << 8) + packet[pos+3];
    udp->length = (packet[pos+4] << 8) + packet[pos+5];
    udp->transport = UDP;
    VERBOSE(printf("udp\n");)
    VERBOSE(printf("srcport: %d, dstport: %d, len: %d\n", udp->srcport, udp->dstport, udp->length);)
    SHOW_RAW(print_packet(header->len, packet, pos, pos, 4);)
    return pos + 8;
}

// Convert an ip struct to a string. The returned buffer is internal, 
// and need not be freed. 
char * iptostr(ip_addr * ip) {
    if (ip->vers == IPv4) {
        inet_ntop(AF_INET, (const void *) &(ip->addr.v4),
                  IP_STR_BUFF, INET6_ADDRSTRLEN);
    } else { // IPv6
        inet_ntop(AF_INET6, (const void *) &(ip->addr.v6),
                  IP_STR_BUFF, INET6_ADDRSTRLEN);
    }
    return IP_STR_BUFF;
}
