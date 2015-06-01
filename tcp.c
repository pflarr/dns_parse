#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/stat.h>
#include "strutils.h"
#include "tcp.h"

// Perform TCP checksum on the given packet. 
// This handles both IPv6 and IPv4 based TCP.
uint16_t tcp_checksum(ip_info *ip, uint8_t *packet, 
                     uint32_t pos, struct pcap_pkthdr *header) {
    unsigned int sum = 0;
    unsigned int i;

    if (ip->src.vers == IPv4) {
        uint32_t srcip = ip->src.addr.v4.s_addr; 
        uint32_t dstip = ip->dst.addr.v4.s_addr; 

        // Put together the psuedo-header preamble for the checksum calculation.
        // I handle the IP's in a rather odd manner and save a few cycles.
        // Instead of arranging things such that for ip d.c.b.a -> cd + ab
        //   I do cb + ad, which is equivalent. 
        sum += (srcip >> 24) + ((srcip & 0xff) << 8);
        sum += (srcip >> 8) & 0xffff;
        sum += (dstip >> 24) + ((dstip & 0xff) << 8);
        sum += (dstip >> 8) & 0xffff;
        sum += ip->proto;
        sum += ip->length;
    } else {
        // IPv6 psuedo header construction.
        uint16_t * src_v6 = ip->src.addr.v6.s6_addr16;
        uint16_t * dst_v6 = ip->dst.addr.v6.s6_addr16;
        for (i=0; i<8; i++) {
            sum += (src_v6[i] >> 8) + ((src_v6[i] & 0xff) << 8);
            sum += (dst_v6[i] >> 8) + ((dst_v6[i] & 0xff) << 8);
        }
        sum += ip->length;
        sum += TCP;
    }

    // Add the TCP Header up to the checksum, which we'll skip.
    for (i=0; i < 16; i += 2) {
        sum += LE_U_SHORT(packet, pos + i);
    }

    // Skip the checksum.
    pos = pos + i + 2;

    // Add the rest of the packet, stopping short of a final odd byte.
    while (pos < header->len - 1) {
        sum += LE_U_SHORT(packet, pos);
        pos += 2;
    }
    // Pad the last, odd byte if present.
    if (pos < header->len) 
        sum += packet[pos] << 8;

    // All the overflow bits should be added to the lower 16, including the
    // overflow from adding the overflow.
    while (sum > 0xffff) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // Take the one's compliment (logical not) and we're done.
    return ~sum;
}

// The one-half second expiration time is chosen simply because it's the 
// shortest time that consistently works. Shorter and you may miss some
// late arriving packets (.1 seconds misses quite a few). Longer and
// it's more likely that continuous sessions will never expire.
#define TCP_EXPIRE_USECS 500000
#define __USEC_RES 1000000
#define is_expired(now, old) (\
    ((long long) (now).tv_sec*__USEC_RES + (now).tv_usec) - \
    ((long long) (old).tv_sec*__USEC_RES + (old).tv_usec)) > \
      TCP_EXPIRE_USECS

// Parse the tcp data, and put it in our lists of streams to be reassembled 
// later.
void tcp_parse(uint32_t pos, struct pcap_pkthdr *header, 
               uint8_t *packet, ip_info *ip, config * conf) {
    // This packet.
    tcp_info * tcp;
    // For traversing the session list.
    tcp_info ** next;
    // Will hold the matching session when we look.
    tcp_info * sess = NULL;
    unsigned int offset;
    uint16_t checksum;
    uint16_t actual_checksum;

    tcp = malloc(sizeof(tcp_info));

    // Get basic TCP header information.
    tcp->next_sess = NULL;
    tcp->next_pkt = NULL;
    tcp->prev_pkt = NULL;
    tcp->ts = header->ts;
    tcp->src = ip->src;
    tcp->dst = ip->dst;
    tcp->srcport = LE_U_SHORT(packet, pos);
    tcp->dstport = LE_U_SHORT(packet, pos+2);
    tcp->sequence = LE_U_INT(packet, pos + 4);
    tcp->ack_num = LE_U_INT(packet, pos + 8);
    tcp->ack = GET_BIT(packet, pos + 13, 5);
    tcp->syn = GET_BIT(packet, pos + 13, 1);
    tcp->fin = GET_BIT(packet, pos + 13, 0);
    tcp->rst = GET_BIT(packet, pos + 13, 2);
    offset = packet[pos + 12] >> 4;

    if ((pos + offset*4) > header->len) {
        fprintf(stderr, "Truncated TCP packet: %d, %d\n", offset, header->len);
        free(tcp);
        return;
    }
    tcp->len = ip->length - offset*4;

    // Ignore packets with a bad checksum
    checksum = LE_U_SHORT(packet, pos + 16);

    actual_checksum = tcp_checksum(ip, packet, pos, header);
    if (checksum != actual_checksum || 
        // 0xffff and 0x0000 are both equal to zero in one's compliment,
        // so these are actually the same.
        (checksum == 0xffff && actual_checksum == 0x0000) ||
        (checksum == 0x0000 && actual_checksum == 0xffff) ) {
        // Do Bad Checksum stuff
        DBG(printf("Bad checksum.");)
        free(tcp);
        return;
    } else

    // Only allocated space for the TCP data if there is any.
    if (tcp->len > 0) {
        tcp->data = malloc(sizeof(char) * (tcp->len));
        memcpy(tcp->data, packet + pos + (offset*4), tcp->len);
    } else
        tcp->data = NULL;

    DBG(printf("This pkt - %p: ", tcp);)
    DBG(tcp_print(tcp);)
    DBG(printf("The head - %p: ", conf->tcp_sessions_head);)
    DBG(tcp_print(conf->tcp_sessions_head);)

    DBG(printf("Finding the matching session.\n");)
    // Keep in mind 'next' is a pointer to the pointer to the next item.
    // Find a matching session, if we have one. 
    // We treat sessions as 1-way communications. The other direction
    // is handled as a separate stream.
    next = &(conf->tcp_sessions_head);
    while (*next != NULL) {
        DBG(printf("Checking: ");)
        DBG(tcp_print(*next);)
        if ( IP_CMP((*next)->src, tcp->src) &&
             IP_CMP((*next)->dst, tcp->dst) && 
             (*next)->srcport == tcp->srcport &&
             (*next)->dstport == tcp->dstport) {

            DBG(printf("Match found:\n  ");)
            DBG(tcp_print(*next);)

            // This is the matching session.
            sess = *next;

            // Assign this to the packet chain.
            sess->next_pkt = tcp;
            tcp->prev_pkt = sess;
            // Since this will be the head, it needs to know where 
            // the next session is.
            tcp->next_sess = sess->next_sess;
            // The current packet is now the head packet of this session.
            sess = tcp;

            // The pointer to the next object should now be set to skip one.
            *next = sess->next_sess;
            // Set sess's next pointer to the old head.
            sess->next_sess = conf->tcp_sessions_head;
            // Then stick our sess back in as the head of the list.
            conf->tcp_sessions_head = sess;
            // We found our session, we're done.
            break;
        } 
        // It doesn't belong to this session, move on to the next.
        next = &(*next)->next_sess;
    }

    // No matching session found.
    if (sess == NULL) {
        DBG(printf("No match found.\n");)
        tcp->next_sess = conf->tcp_sessions_head;
        conf->tcp_sessions_head = tcp; 
    }

    return;
}

// Go through the list of tcp sessions and expire any old ones.
// (Old is defined by TCP_EXPIRE_USECS).
// The expired sessions are reassembled (or at least an attempt is made).
// The reassembled data is handed of the the dns parser, and we
// output the results.
// Now should be the timeval that came with the most recent packet.
// Now can also be NULL, which will expire everything.
void tcp_expire(config * conf, const struct timeval * now ) {
    tcp_info * head = NULL;
    tcp_info ** ptr = &head;
    tcp_info ** next = &(conf->tcp_sessions_head);

    while (*next != NULL) {
        // Check to see if this session is expired based on the time given.
        if (now == NULL || is_expired(*now, (*next)->ts)) {
            // We need this because we'll probably end up free the 
            // first packet of the session.
            tcp_info * next_sess = (*next)->next_sess;
            // Add this session to the list of of returned sessions

            *ptr = tcp_assemble(*next);
            // *next is probably freed now, unless it was returned as *ptr.

            // Remove this session from the main session list.
            *next = next_sess;

            // If the assembled stream was empty, skip to the next one.
            DBG(printf("*ptr %p\n", *ptr);)
            if (*ptr == NULL) {
                continue;
            }

            // Set ptr to point to the where the next expired session
            // should be added to the list.
            ptr = &(*ptr)->next_sess;
            // Clear that pointer.
            *ptr = NULL;
        } else {
            // Skip this session, it isn't expired.
            next = &(*next)->next_sess;
        }
    }

    // Step through all the assembled sessions, dns parse the data, and
    // output it.
    //
    // The madness you're about to experience stems from the fact that a 
    // session may contain multiple DNS requests. Additionally, we might
    // just have junk, and need a rough way of telling the difference.
    // With TCP DNS, the DNS data is prepended with a two byte length,
    // so we at least know how long it is. 
    while (head != NULL) {
        // There is a possiblity that this session won't start at the
        // the beginning of the data; that we've caught a session mid-stream.
        // Assuming we have expired it at a reasonable end, we can use the 
        // length bytes to test our start position. If our length bytes allow
        // us to correctly jump the length of the packet, then we're good.
        // (Probably)
        unsigned long long offset;
        unsigned long long dns_len;
        char offset_found = 0;
        for (offset=0; offset < head->len-1; offset++) {
            unsigned long long pos = offset;
            while (pos + 1 < head->len) {
                dns_len = TCP_DNS_LEN(head->data, pos);
                // We shouldn't ever have an offset of 0.
                if (dns_len == 0) break;
                pos += 2 + dns_len;
            }
            // We've found the right offset (probably 0).
            if (pos == head->len) {
                offset_found = 1;
                break;
            }
        }

        // If we couldn't find the right offset, just try an offset of 
        // zero as long as that offset isn't longer than all of our data.
        if (offset_found == 0) {
            if   (head->len > 2 && 
                  TCP_DNS_LEN(head->data, 0) < head->len &&
                  // We should have more data than fits in a DNS header.
                  // (12 bytes).
                  TCP_DNS_LEN(head->data, 0) > 12 ) {
                offset = 0;
            } else { 
                char * bad_data = escape_data(head->data, 0, head->len);
                print_ts(&(head->ts), conf);
                printf(", Bad TCP stream: %s\n", bad_data);
                free(bad_data);
            }
        }

        // Go through the stream offset by offset, create a fake packet
        // header (and packet data), and hand both off to the DNS parser.
        // The results are output.
        if (offset + 1 < head->len) {
            dns_len = TCP_DNS_LEN(head->data, offset);
        } else {
            // Skip trying to parse this.
            dns_len = head->len;
        }
        while (offset + dns_len < head->len) {
            dns_info dns;
            ip_info ip;
            transport_info trns;
            struct pcap_pkthdr header;
            uint32_t pos;

            // Create a fake packet header, transport and IP structs.
            header.ts = head->ts;
            header.caplen = head->len;
            header.len = head->len;
            trns.srcport = head->srcport;
            trns.dstport = head->dstport;
            trns.length = head->len;
            trns.transport = TCP;
            ip.src = head->src;
            ip.dst = head->dst;
            ip.proto = 0x06;
            DBG(printf("Parsing DNS (TCP).\n");)
            // Parse the DNS data from the point after the prepended len.
            // We must parse the whole packet, otherwise we get off in our
            // stream, so we set the parse_all flag.
            pos = dns_parse(offset+2, &header, head->data, &dns, conf, FORCE);
            if (pos != 0) {
                // Print the data if there wasn't an error.
                print_summary(&ip, &trns, &dns, &header, conf);
            }

            if (pos != offset + 2 + dns_len) {
                // If these don't match up, then there is no point in
                // continuing for this session.
                DBG(
                    fprintf(stderr, "Mismatched TCP lengths: %u, %llu.\n",
                            pos, (offset + 2 + dns_len));
                    fflush(stderr);
                )
                break;
            }
            // Move on to the next DNS header in the stream.
            offset += 2 + dns_len;
            if (offset + 1 < head->len) {
                // We don't want to try to parse the length if we're past
                // the end of the packet.
                dns_len = TCP_DNS_LEN(head->data, offset);
            }
        }

        // Free this TCP stream and it's data.
        tcp_info * tmp;
        tmp = head;
        head = head->next_sess;
        free(tmp->data);
        free(tmp);
    }
}

// Go through the tcp starting at 'base'. Hopefully it will all be there.
// Otherwise assemble as much as you can. 
// In doing this all child packets are freed (and their data chunks), 
// and a allocation is made. This is attached to the 'base' tcp_info object.
// That tcp_info object has all its point sess and packet pointers set to
// NULL.
// It is assumed that the total data portion will fit in memory (twice actually,
// since the original allocations will be freed after assembly is complete).
tcp_info * tcp_assemble(tcp_info * base) {
    tcp_info **curr;
    tcp_info *origin = NULL;
    uint32_t curr_seq;
    // We'll keep track of the total size of data to copy.
    long long total_length = 0;
    // Where we are in the copying.
    long long pos = 0;
    // The actual data pointer for the final data.
    uint8_t * final_data;

    // All the pieces of data to reassemble.
    char ** data_chain;
    // The sizes of each piece.
    uint32_t * data_lengths;
    size_t dc_i = 0;
    uint32_t i;

    DBG(printf("In TCP_assembly.\n");)
    DBG(printf("Assembling:\n");)
    DBG(tcp_print(base);)

    // Figure out the max length of the data chain.
    // Move base along to be the oldest packet, so we can work on this
    // from the start rather than the end.
    for (curr=&base; *curr != NULL; curr = &(*curr)->prev_pkt) {
        dc_i++;
        base = *curr;
    }
    DBG(printf("Making the data_chain vars.\n");)
    data_chain = calloc(dc_i, sizeof(char *));
    data_lengths = calloc(dc_i, sizeof(uint32_t));

    // Find the first syn packet
    curr = &base;
    while (*curr != NULL) {
        DBG(tcp_print(*curr);)
        if ((*curr)->syn) {
            // Make note of this packet, it's the object we'll return.
            origin = *curr;
            curr_seq = (*curr)->sequence;
            DBG(printf("Found first sequence #: %x\n", curr_seq);)
            break;
        }
        curr = &(*curr)->next_pkt;
    }

    if (origin == NULL) {
        // If we fail to find the syn packet, use the earliest packet.
        // This means we might jump in in the middle of a session, but
        // we may still be able to pull out some DNS data if we're lucky.
        origin = base;
        curr_seq = base->sequence;
    }

    // Gather all the bits of data, in order. 
    // The chain is destroyed bit by bit, except for the last tcp object.
    // Skip all this if the origin is NULL, since we don't have a starting
    // point anyway.
    dc_i = 0;
    while (base != NULL && origin != NULL) {
        // Search for the packet with the next sequence number that has 
        // non-zero length.
        tcp_info ** next_best = NULL;
        for (curr = &base; *curr != NULL; curr = &(*curr)->next_pkt) {
            if ((*curr)->sequence == curr_seq) {
                if ((*curr)->len > 0) {
                    // We found a packet at that sequence with data, it 
                    // should be what we want.
                    break;
                } else if (next_best == NULL) {
                    // A zero length packet will do if we can't find anything
                    // better.
                    next_best = curr;
                }
            }
        }
        // If we didn't find a matching packet with data, use the least
        // recent zero length packet. If that should be the origin, but 
        // isn't, adjust the origin packet.
        if (*curr == NULL && next_best != NULL) {
            if (*next_best != NULL) {
                curr = next_best;
            }
        }

        // Set the origin to this packet if they have the same sequence.
        // Guarantees that the origin will be a packet removed from the
        // packet list (and thus not thrown away later).
        // This will only occur for the first sequence number.
        if (*curr != NULL && (origin->sequence == (*curr)->sequence)) {
            origin = *curr;
        }

        if (*curr != NULL) {
            DBG(printf("Current assembly packet: ");)
            DBG(tcp_print(*curr);)
            tcp_info * tmp;
            //DBG(print_packet((*curr)->len, (*curr)->data, 0, (*curr)->len, 8);)
            // We found a match.
            // Save the data and it's length.
            data_chain[dc_i] = (char*) (*curr)->data;
            data_lengths[dc_i] = (*curr)->len;
            total_length += (*curr)->len;
            dc_i++;

            // Look for the next sequence number.
            DBG(printf("curr_seq, seq: %x, %x\n", curr_seq, (*curr)->sequence);)
            if ((*curr)->len == 0) {
                curr_seq++;
            } else {
                curr_seq += (*curr)->len;
            }

            // Remove this packet from the list.
            tmp = *curr;
            *curr = (*curr)->next_pkt;
            // Free that packet object as long as it isn't the origin.
            if (tmp != origin) {
                // The data part will be freed separately in a bit.
                DBG(printf("Freeing: %p\n", tmp);)
                free(tmp);
            }

        } else {
            // We didn't find a match. We're probably done now.
            break;
        }
        // Start over from the beginning of the list every time.
        curr = &base;
    }

    // Free any remaining packet objects and their data.
    while (base != NULL) {
        tcp_info * next = base->next_pkt;
        DBG(printf("Free unused packet:\n");)
        DBG(tcp_print(base);)
        free(base->data);
        free(base);
        base = next;
    }

    DBG(printf("Total_length: %lld\n", total_length);)

    // Make the final data struct.
    // This could be seriously freaking huge. We'll ignore that for now.
    // It should be fine, in theory, thanks to virtual memory and big disks,
    // but it's good this is only DNS data, right?
    // Combine the data.
    // We'll skip combining the data, and just free the chain, if there 
    // isn't any data to deal with.
    if (total_length > 0) {
        final_data = malloc(sizeof(uint8_t) * total_length);
        for(i=0; i < dc_i; i++) {
            if (data_chain[i] != NULL) { 
                memcpy(final_data + pos, data_chain[i], data_lengths[i]);
                pos += data_lengths[i];
                DBG(printf("data_chain[%d] free: ", i);)
                free(data_chain[i]);
            }
        }
    }

    DBG(printf("data_chain, lengths, free.\n");)
    free(data_chain);
    free(data_lengths);

    if (total_length == 0) {
        // There was no data in the session to return.
        DBG(printf("Empty session:%p.\n", origin);)
        if (origin != NULL) {
            DBG(printf("Bleh\n");)
            free(origin);
        }
        return NULL;
    }

    // Set the the first packet in the session as our return value.
    origin->data = final_data;
    origin->len = total_length;

    DBG(printf("TCP assembly finished.\n");)
    DBG(printf("origin - ");) 
    DBG(tcp_print(origin);)

    return origin;
}

// Save all unresolved sessions to disk. The path to the save file can be
// set with the -s option at runtime. 
// File format:
// Each tcp_info object and it's data are saved in turn, starting with
// conf->tcp_sessions_head. All the packets of each session are saved
// before moving to the next session.
// When saving a session, the tcp_info object has all it's pointers
// set to NULL. The prev_pkt pointer will be 1 if there is another
// packet in the session after this one. 
void tcp_save_state(config * conf) {
    FILE * outfile = fopen(conf->TCP_STATE_PATH,"w");
    tcp_info * next = conf->tcp_sessions_head;
    tcp_info * curr_pkt;

    if (outfile == NULL) {
        fprintf(stderr, "Could not open tcp state file.\n");
        fclose(outfile);
        return;
    }

    while (next != NULL) {
        curr_pkt = next;
        next = next->next_sess;
        while (curr_pkt != NULL) {
            tcp_info * prev_pkt = curr_pkt->prev_pkt;
            uint8_t * data = curr_pkt->data;
            uint32_t len = curr_pkt->len;
            size_t written;
            // Clear all or pointers, or turn them into flags.
            curr_pkt->next_sess = NULL;
            curr_pkt->next_pkt = NULL;
            // All we need to know is whether there is a prev. packet.
            curr_pkt->prev_pkt = (prev_pkt == NULL) ? (NULL+1) : NULL;
            curr_pkt->data = NULL;
            written = fwrite(curr_pkt, sizeof(tcp_info), 1, outfile);
            if (written != 1) {
                fprintf(stderr, "Could not write to tcp state file.\n");
                fclose(outfile);
                return;
            }
            free(curr_pkt);
            written = fwrite(data, sizeof(uint8_t), len, outfile);
            if (written != len) {
                fprintf(stderr, "Could not write to tcp state file(data).\n");
                fclose(outfile);
                free(data);
                return;
            }
            free(data);
            curr_pkt = prev_pkt;
        }
    }
    fclose(outfile);
}

// Look for a saved TCP state data file, and try to load the data from it.
tcp_info * tcp_load_state(config * conf) {
    FILE * infile;
    struct stat i_stat;
    int ret = stat(conf->TCP_STATE_PATH, &i_stat);
    size_t read;
    tcp_info * pkt;
    tcp_info * prev = NULL;
    tcp_info * first_sess = NULL;
    tcp_info ** sess = &first_sess;
    int has_prev = 0;

    if (ret != 0) {
        // No prior state file.
        fprintf(stderr, "No prior tcp state file.\n");
        return NULL;
    }

    infile = fopen(conf->TCP_STATE_PATH, "r");
    if (infile == NULL) {
        fprintf(stderr, "Could not open existing tcp state file.\n");
        return NULL;
    }

    pkt = malloc(sizeof(tcp_info));
    read = fread(pkt, sizeof(tcp_info), 1, infile);
    while (read != 0) {
        // If the last packet had a another packet in the session,
        // then point it to this one and vice versa. 
        // Note: Don't forget the packets are in most recent first order.
        if (has_prev == 1) {
            prev->prev_pkt = pkt;
            pkt->next_pkt = prev;
        } else {
            // The last packet was the last in a session. 
            // Start a new session.
            *sess = pkt; 
            sess = &(pkt->next_sess);
        }
        has_prev = (pkt->prev_pkt == NULL);
        pkt->prev_pkt = NULL;

        pkt->data = malloc(sizeof(uint8_t) * pkt->len);
        read = fread(pkt->data, sizeof(uint8_t), pkt->len, infile);
        if (read != pkt->len) {
            // We are failing to free the memory of anything read in so far.
            // It's probably not a big deal.
            fprintf(stderr, "Tcp state file read error (data).\n");
            return NULL;
        }

        prev = pkt;
        pkt = malloc(sizeof(tcp_info));
        read = fread(pkt, sizeof(tcp_info), 1, infile);
    }

    // Since the last read was of length zero, (all other cases return or 
    // continue) go ahead and free our last allocated object.
    free(pkt);
    fclose(infile);

    return first_sess;
}

// Print a tcp_info object. For debugging.
void tcp_print(tcp_info * tcp) {
    if (tcp == NULL) {
        printf("NULL tcp object\n");
    } else {
        printf("%p %s:%d ", tcp, iptostr(&tcp->src), tcp->srcport);
        printf("-> %s:%d, seq: %x, safr: %d%d%d%d, len: %u\n", 
               iptostr(&tcp->dst), tcp->dstport,
               tcp->sequence, tcp->syn, tcp->ack,
               tcp->fin, tcp->rst, tcp->len);
    }
}
