#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"
#include "packet.h"
#include "ip.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

u8 ALLMAC[ETH_ALEN] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x05};
extern ustack_t *instance;

time_t start_time;

pthread_mutex_t mospf_lock;

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;
	// printf("my rid =====%d\n", instance->router_id);
	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}
	time(&start_time);
	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);

void mospf_run()
{
	pthread_t hello, lsu, nbr;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
}

void *sending_mospf_hello_thread(void *param)
{
	int len = MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE + IP_BASE_HDR_SIZE + ETHER_HDR_SIZE;
	while(1) {
		iface_info_t * tmp_iface;
		list_for_each_entry(tmp_iface, &instance->iface_list, list) {
			char * packet = malloc(len);
			struct ether_header * eh = (struct ether_header *)packet;
			struct iphdr * send_ip = packet_to_ip_hdr(packet);
			struct mospf_hdr * send_mospf = (struct mospf_hdr *)((char *)send_ip + IP_BASE_HDR_SIZE);
			struct mospf_hello * send_hello = (struct mospf_hello *)((char *)send_mospf + MOSPF_HDR_SIZE);
			mospf_init_hello(send_hello, tmp_iface->mask);
			mospf_init_hdr(send_mospf, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, \
				instance->router_id, instance->area_id);
			send_mospf->checksum = mospf_checksum(send_mospf);
			ip_init_hdr(send_ip, tmp_iface->ip, MOSPF_ALLSPFRouters, \
				MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE + IP_BASE_HDR_SIZE, IPPROTO_MOSPF);			
			eh->ether_type = htons(ETH_P_IP);
			memcpy(eh->ether_shost, tmp_iface->mac, ETH_ALEN);
			memcpy(eh->ether_dhost, ALLMAC, ETH_ALEN);
			iface_send_packet(tmp_iface, packet, len);
		}
		sleep(MOSPF_DEFAULT_HELLOINT);
	}
	// free(packet);
	return NULL;
}

void *checking_nbr_thread(void *param)
{
	while(1) {
		pthread_mutex_lock(&mospf_lock);
		u8 time_usage = (u8)(time(NULL) - start_time);
		iface_info_t * tmp_iface;
		mospf_nbr_t * tmp_nbr, * q;
		list_for_each_entry(tmp_iface, &instance->iface_list, list) 
			list_for_each_entry_safe(tmp_nbr, q, &tmp_iface->nbr_list, list) 
				if(time_usage - tmp_nbr->alive >= MOSPF_NEIGHBOR_TIMEOUT){
					list_delete_entry(&tmp_nbr->list);
					free(tmp_nbr);
				}
		pthread_mutex_unlock(&mospf_lock);
		sleep(1);
	}
	return NULL;
}

void handle_send_lsu() {
	iface_info_t * tmp_iface;
	mospf_nbr_t * tmp_nbr;
	int ttl_nbr = 0;
	list_for_each_entry(tmp_iface, &instance->iface_list, list)
		ttl_nbr += tmp_iface->num_nbr ? tmp_iface->num_nbr : 1;
	struct mospf_lsa * preserve_lsa = (struct mospf_lsa *)malloc(ttl_nbr * MOSPF_LSA_SIZE);
	struct mospf_lsa * lsa = preserve_lsa;
	list_for_each_entry(tmp_iface, &instance->iface_list, list) {
		if(0 == tmp_iface->num_nbr) {
			lsa->mask = htonl(tmp_iface->mask);
			lsa->subnet = htonl(tmp_iface->ip & tmp_iface->mask);
			lsa->rid = htonl(0x0);
			lsa++;
		}
		list_for_each_entry(tmp_nbr, &tmp_iface->nbr_list, list) {
			lsa->mask = htonl(tmp_nbr->nbr_mask);
			lsa->subnet = htonl(tmp_nbr->nbr_ip & tmp_nbr->nbr_mask);
			lsa->rid = htonl(tmp_nbr->nbr_id);
			lsa++;
		}
	}
	instance->sequence_num++;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;
	list_for_each_entry(tmp_iface, &instance->iface_list, list) 
		list_for_each_entry(tmp_nbr, &tmp_iface->nbr_list, list) {
			int len = MOSPF_HDR_SIZE + MOSPF_LSA_SIZE * ttl_nbr + \
				MOSPF_LSU_SIZE + IP_BASE_HDR_SIZE + ETHER_HDR_SIZE;
			char * packet = malloc(len);
			struct iphdr * send_ip = packet_to_ip_hdr(packet);
			struct mospf_hdr * send_mospf = (struct mospf_hdr *)((char *)send_ip + IP_BASE_HDR_SIZE);
			struct mospf_lsu * send_lsu = (struct mospf_lsu *)((char *)send_mospf + MOSPF_HDR_SIZE);
			struct mospf_lsa * send_lsa = (struct mospf_lsa *)((char *)send_lsu + MOSPF_LSU_SIZE);
			memcpy(send_lsa, preserve_lsa, ttl_nbr * MOSPF_LSA_SIZE);
			mospf_init_lsu(send_lsu, ttl_nbr);
			mospf_init_hdr(send_mospf, MOSPF_TYPE_LSU, MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + \
				MOSPF_LSA_SIZE * ttl_nbr, instance->router_id, instance->area_id);
			send_mospf->checksum = mospf_checksum(send_mospf);
			ip_init_hdr(send_ip, tmp_iface->ip, tmp_nbr->nbr_ip, len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
			ip_send_packet(packet, len);
		}
	free(preserve_lsa);
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	struct mospf_hello * m_hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);
	int find = 0, change = 0;
	mospf_nbr_t * tmp;
	pthread_mutex_lock(&mospf_lock);
	if(!list_empty(&iface->nbr_list)) 
		list_for_each_entry(tmp, &iface->nbr_list, list) 
			if(tmp->nbr_id == ntohl(mospf->rid)) {
				tmp->alive = (u8)(time(NULL) - start_time);
				find = 1;
				break;
			}
	if(0 == find) {
		tmp = (mospf_nbr_t *)malloc(sizeof(mospf_nbr_t));
		tmp->nbr_id = ntohl(mospf->rid);
		tmp->nbr_ip = ntohl(ip->saddr);
		tmp->nbr_mask = ntohl(m_hello->mask);
		tmp->alive = (u8)(time(NULL) - start_time);
		list_add_tail(&tmp->list, &iface->nbr_list);
		iface->num_nbr++;
		change = 1;
	}
	pthread_mutex_unlock(&mospf_lock);
	if(change)
		handle_send_lsu();
		
}

void print_database() {
	mospf_db_entry_t * tmp;
	fprintf(stdout, "RID\t\t\tSUBNET\t\t\tMASK\t\t\tNEIGHBOR\n");
	list_for_each_entry(tmp, &mospf_db, list) {
		for(int i=0;i<tmp->nadv;i++) {
			fprintf(stdout, IP_FMT"\t\t\t"IP_FMT"\t\t\t"IP_FMT"\t\t\t"IP_FMT"\n",LE_IP_FMT_STR(tmp->rid), LE_IP_FMT_STR(tmp->array[i].subnet),\
			 LE_IP_FMT_STR(tmp->array[i].mask), LE_IP_FMT_STR(tmp->array[i].rid));
		}
	}
}

void *sending_mospf_lsu_thread(void *param)
{
	while(1) {
		print_database();
		pthread_mutex_lock(&mospf_lock);
		instance->lsuint--;
		pthread_mutex_unlock(&mospf_lock);
		if(instance->lsuint <= 0) 
			handle_send_lsu();
		sleep(1);
	}
	return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	struct iphdr * ip = packet_to_ip_hdr(packet);
	struct mospf_hdr * mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	struct mospf_lsu * lsu = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
	struct mospf_lsa * lsa = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);
	mospf_db_entry_t * tmp_entry;
	int find = 0;
	pthread_mutex_lock(&mospf_lock);
	list_for_each_entry(tmp_entry, &mospf_db, list) {
		if(tmp_entry->rid == ntohl(mospf->rid)){
			find = 1;
			if(tmp_entry->seq < ntohs(lsu->seq)) {
				tmp_entry->nadv = ntohl(lsu->nadv);
				free(tmp_entry->array);
				tmp_entry->array = malloc(MOSPF_LSA_SIZE * tmp_entry->nadv);
				memcpy(tmp_entry->array, lsa, MOSPF_LSA_SIZE * ntohl(lsu->nadv));
				for(int i=0;i<tmp_entry->nadv;i++) {
					tmp_entry->array[i].subnet = ntohl(tmp_entry->array[i].subnet);
					tmp_entry->array[i].mask = ntohl(tmp_entry->array[i].mask);
					tmp_entry->array[i].rid = ntohl(tmp_entry->array[i].rid);
				}
			}
			break;
		}
	}
	if(0 == find) {
		tmp_entry = malloc(sizeof(mospf_db_entry_t));
		tmp_entry->rid = ntohl(mospf->rid);
		tmp_entry->seq = ntohs(lsu->seq);
		tmp_entry->nadv = ntohl(lsu->nadv);
		tmp_entry->array = malloc(MOSPF_LSA_SIZE * ntohl(lsu->nadv));
		memcpy(tmp_entry->array, lsa, MOSPF_LSA_SIZE * ntohl(lsu->nadv));
		for(int i=0;i<tmp_entry->nadv;i++) {
			tmp_entry->array[i].subnet = ntohl(tmp_entry->array[i].subnet);
			tmp_entry->array[i].mask = ntohl(tmp_entry->array[i].mask);
			tmp_entry->array[i].rid = ntohl(tmp_entry->array[i].rid);
		}
		list_add_tail(&tmp_entry->list, &mospf_db);
	}
	pthread_mutex_unlock(&mospf_lock);
	if(--lsu->ttl) {
		mospf->checksum = mospf_checksum(mospf);
		iface_info_t * tmp_iface;
		mospf_nbr_t * tmp_nbr;
		list_for_each_entry(tmp_iface, &instance->iface_list, list){
			if(tmp_iface == iface)
				continue;
			list_for_each_entry(tmp_nbr, &tmp_iface->nbr_list, list) {
				if(tmp_nbr->nbr_id == ntohl(mospf->rid))
					continue;
				char * send_packet = (char *)malloc(len);
				ip_init_hdr(ip, tmp_iface->ip, tmp_nbr->nbr_ip, len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
				memcpy(send_packet, packet, len);
				ip_send_packet(send_packet, len);
			}
		}
	}
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum, type = %d;rid = %d", mospf->type, ntohl(mospf->rid));
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	// log(DEBUG, "received mospf packet, type: %d", mospf->type);

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}
