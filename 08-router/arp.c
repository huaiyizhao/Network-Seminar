#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "ip.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	//printf("in arp_send_request\n");
	char * packet = (char *)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_header * header = (struct ether_header *)packet;
	memset(header->ether_dhost, 0xff, ETH_ALEN);
	memcpy(header->ether_shost, iface->mac, ETH_ALEN);
	header->ether_type = htons(ETH_P_ARP);

	struct ether_arp * arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	arp->arp_pro = htons(0x0800);
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_hln = ETH_ALEN;
	arp->arp_pln = 4;
	arp->arp_op = htons(ARPOP_REQUEST);
	memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
	arp->arp_spa = htonl(iface->ip);
	// memset(arp->arp_tha, 0, ETH_ALEN);
	arp->arp_tpa = htonl(dst_ip);

	iface_send_packet(iface, packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
	//fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
}


// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	//printf("in arp_send_reply\n");
	// printf("receive mac: %s", req_hdr->arp_sha);
	char * packet = (char *)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_header * header = (struct ether_header *)packet;
	memcpy(header->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	memcpy(header->ether_shost, iface->mac, ETH_ALEN);
	header->ether_type = htons(ETH_P_ARP);

	struct ether_arp * arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	arp->arp_pro = htons(0x0800);
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_hln = ETH_ALEN;
	arp->arp_pln = 4;
	arp->arp_op = htons(ARPOP_REPLY);
	memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
	arp->arp_spa = htonl(iface->ip);
	arp->arp_tpa = htonl(req_hdr->arp_spa);
	memcpy(arp->arp_tha, req_hdr->arp_sha, ETH_ALEN);

	 //printf("goto send arp reply iface_send_packet\n");
	// printf("send mac: %s", arp->arp_tha);
	// printf("----> reply: ip => "IP_FMT"\n", HOST_IP_FMT_STR(arp->arp_tpa));
	iface_send_packet(iface, packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));

	//fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp * arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	if(ntohs(arp->arp_op) == 1 && ntohl(arp->arp_tpa) == iface->ip){ //request
		//printf("receive arp request\n");
		arp_send_reply(iface, arp);
		arpcache_insert(arp->arp_spa, arp->arp_sha);
	}

	if(ntohs(arp->arp_op) == 2) {
		//printf("receive arp reply\n");
		arpcache_insert(arp->arp_spa, arp->arp_sha);
	}
	
	//fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
}
// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	//printf("in send_by_arp\n");
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		//printf("found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		//printf("lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}


