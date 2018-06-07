#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	// fprintf(stdout, "TODO: determine the direction of this packet.\n");
	struct iphdr *ip = packet_to_ip_hdr(packet);
	iface_info_t * siface = longest_prefix_match(ntohl(ip->saddr))->iface;
	iface_info_t * diface = longest_prefix_match(ntohl(ip->daddr))->iface;
	if(siface == nat.internal_iface && diface == nat.external_iface)
		return DIR_OUT;

	if(siface == nat.external_iface && ntohl(ip->daddr) == nat.external_iface->ip)
		return DIR_IN;

	return DIR_INVALID;
}

struct nat_mapping * find_nat_map(char * packet, int dir)
{
	struct iphdr * ip = packet_to_ip_hdr(packet);
	struct tcphdr * tcp = packet_to_tcp_hdr(packet);
	u32 ser_ip = (dir == DIR_IN) ? ntohl(ip->saddr) : ntohl(ip->daddr);
	u32 ser_port = (dir == DIR_IN) ? ntohs(tcp->sport) : ntohs(tcp->dport);
	char hash_str[6];
	memcpy(hash_str, &ser_ip, 4);
	memcpy(hash_str + 4, &ser_port, 2);
	struct nat_mapping * map = (struct nat_mapping *)&nat.nat_mapping_list[hash8(hash_str, 6)];
	if(dir == DIR_OUT) {
		u32 in_ip = ntohl(ip->saddr);
		u16 in_port = ntohs(tcp->sport);
		struct nat_mapping * entry = NULL;
		list_for_each_entry(entry, (struct list_head *)map, list) 
			if(entry->internal_ip == in_ip && entry->internal_port == in_port)
				return entry;
		return NULL;
	}

	if(dir == DIR_IN) {
		u32 ex_ip = ntohl(ip->daddr);
		u16 ex_port = ntohs(tcp->dport);
		struct nat_mapping * entry = NULL;
		list_for_each_entry(entry, (struct list_head *)map, list) {
			if(entry->external_ip == ex_ip && entry->external_port == ex_port)
				return entry;
		}
		return NULL;
	}

	return NULL;
}

struct nat_mapping * insert_map(char * packet)// must be DIR_OUT
{
	u16 get_port, i;
	for(i=0;i<65536;i++){
		if(nat.assigned_ports[i] == 0){
			get_port = i;
			nat.assigned_ports[i] = 1;
			break;
		}
	}
	if(i == 65536)
		return NULL;
	struct iphdr * ip = packet_to_ip_hdr(packet);
	struct tcphdr * tcp = packet_to_tcp_hdr(packet);
	u32 ser_ip = ntohl(ip->daddr);
	u32 ser_port = ntohs(tcp->dport);
	char hash_str[6];
	memcpy(hash_str, &ser_ip, 4);
	memcpy(hash_str + 4, &ser_port, 2);
	struct nat_mapping * map = (struct nat_mapping *)&nat.nat_mapping_list[hash8(hash_str, 6)];
	struct nat_mapping * new = malloc(sizeof(struct nat_mapping));
	u32 in_ip = ntohl(ip->saddr);
	u16 in_port = ntohs(tcp->sport);
	new->internal_ip = in_ip;
	new->internal_port = in_port;
	new->external_ip = nat.external_iface->ip;
	new->external_port = get_port;
	time(&new->update_time);
	list_add_tail(&new->list, &map->list);
	return new;
}
// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	// fprintf(stdout, "TODO: do translation for this packet.\n");
	struct iphdr * ip = packet_to_ip_hdr(packet);
	struct tcphdr * tcp = packet_to_tcp_hdr(packet);
	u8 FIN = tcp->flags & TCP_FIN;
	u8 SYN = tcp->flags & TCP_SYN;
	u8 RST = tcp->flags & TCP_RST;
	u8 PSH = tcp->flags & TCP_PSH;
	u8 ACK = tcp->flags & TCP_ACK;
	u8 URG = tcp->flags & TCP_URG;
	// printf("dir = %d;;%d,%d,%d,%d,%d,%d\n", dir, FIN, SYN, RST, PSH, ACK, URG);
	struct nat_mapping * find_map = find_nat_map(packet, dir);
	pthread_mutex_lock(&nat.lock);
	if(dir == DIR_OUT) {
		if(!find_map){
			find_map = insert_map(packet);
		}
		if(find_map){
			ip->saddr = htonl(find_map->external_ip);
			tcp->sport = htons(find_map->external_port);
			ip->checksum = ip_checksum(ip);
			tcp->checksum = tcp_checksum(ip, tcp);
			find_map->conn.internal_seq_end = ntohl(tcp->seq);
			// printf("conn.internal_seq_end = %d\n", find_map->conn.internal_seq_end);
			find_map->conn.internal_ack = ACK ? ntohl(tcp->ack) : find_map->conn.internal_ack;
			find_map->conn.internal_fin = RST ? 2 : FIN ? 1 : find_map->conn.internal_fin;
			// printf("conn.internal_fin = %d\n", find_map->conn.internal_fin);

			time(&find_map->update_time);
		}
	}

	if(dir == DIR_IN) {
		if(find_map) {
			ip->daddr = htonl(find_map->internal_ip);
			tcp->dport = htons(find_map->internal_port);
			ip->checksum = ip_checksum(ip);
			tcp->checksum = tcp_checksum(ip, tcp);
			find_map->conn.external_seq_end = ntohl(tcp->seq);
			find_map->conn.external_ack = ACK ? ntohl(tcp->ack) : find_map->conn.external_ack;
			find_map->conn.external_fin = RST ? 2 : FIN ? 1 : find_map->conn.external_fin;
			// printf("conn.external_fin = %d\n", find_map->conn.external_fin);
			time(&find_map->update_time);
		}
	}
	pthread_mutex_unlock(&nat.lock);

	ip_send_packet(packet, len);
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	while (1) {
		pthread_mutex_lock(&nat.lock);	
		time_t time_now = time(NULL);
		for(int i=0;i<HASH_8BITS;i++) {
			if(!list_empty(&nat.nat_mapping_list[i])){
				struct nat_mapping * entry, * q;
				struct list_head * head = &nat.nat_mapping_list[i];
				list_for_each_entry_safe(entry, q, head, list) 
				{
					// printf("%d,%d,%d,%d,%d,%d\n",entry->conn.internal_fin,entry->conn.external_fin,entry->conn.internal_ack,entry->conn.external_seq_end,entry->conn.external_ack,entry->conn.internal_seq_end );
					if(entry->conn.internal_fin == 2 || entry->conn.external_fin == 2 \
						|| (entry->conn.internal_fin == 1 && entry->conn.external_fin == 1 \
							&& entry->conn.internal_ack >= entry->conn.external_seq_end \
							&& entry->conn.external_ack >= entry->conn.internal_seq_end) \
						|| time_now - entry->update_time > 60) 
					{
						list_delete_entry(&entry->list);
						free(entry);
					}
				}
			}
			
		}
		pthread_mutex_unlock(&nat.lock);
		// fprintf(stdout, "TODO: sweep finished flows periodically.\n");
		sleep(1);
	}

	return NULL;
}

// initialize nat table
void nat_table_init()
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	nat.internal_iface = if_name_to_iface("n1-eth0");
	nat.external_iface = if_name_to_iface("n1-eth1");
	if (!nat.internal_iface || !nat.external_iface) {
		log(ERROR, "Could not find the desired interfaces for nat.");
		exit(1);
	}

	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

// destroy nat table
void nat_table_destroy()
{
	pthread_mutex_lock(&nat.lock);

	for (int i = 0; i < HASH_8BITS; i++) {
		struct list_head *head = &nat.nat_mapping_list[i];
		struct nat_mapping *mapping_entry, *q;
		list_for_each_entry_safe(mapping_entry, q, head, list) {
			list_delete_entry(&mapping_entry->list);
			free(mapping_entry);
		}
	}

	pthread_kill(nat.thread, SIGTERM);

	pthread_mutex_unlock(&nat.lock);
}
