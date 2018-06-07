#include "packet.h"
#include "types.h"
#include "ether.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
 
extern ustack_t *instance;

void iface_send_packet(iface_info_t *iface, const char *packet, int len)
{
	struct sockaddr_ll addr;
	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = iface->index;
	addr.sll_halen = ETH_ALEN;
	addr.sll_protocol = htons(ETH_P_ARP);
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(addr.sll_addr, eh->ether_dhost, ETH_ALEN);

	if (sendto(iface->fd, packet, len, 0, (const struct sockaddr *)&addr,
				sizeof(struct sockaddr_ll)) < 0) {
 		perror("Send raw packet failed");
	}
}

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	// TODO: implement the broadcast process here
	struct list_head * head = &(instance->iface_list);
	struct list_head * t = head;
	if(!list_empty(head)){
		while(t->next && t->next != head){
			iface_info_t * face = (iface_info_t *)(t->next);
			if(strcmp(face->name, iface->name))
				//printf("-->%s\n", face->name);
				iface_send_packet(face, packet, len);
			t = t->next;
		}
	}
	//fprintf(stdout, "TODO: implement the broadcast process here.\n");
}
