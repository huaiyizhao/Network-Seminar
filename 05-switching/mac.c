#include "mac.h"
#include "headers.h"
#include "log.h"

mac_port_map_t mac_port_map;

void init_mac_hash_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	pthread_mutexattr_init(&mac_port_map.attr);
	pthread_mutexattr_settype(&mac_port_map.attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mac_port_map.lock, &mac_port_map.attr);

	pthread_create(&mac_port_map.tid, NULL, sweeping_mac_port_thread, NULL);
}

void destory_mac_hash_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *tmp, *entry;
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		if (!entry) 
			continue;

		tmp = entry->next;
		while (tmp) {
			entry->next = tmp->next;
			free(tmp);
			tmp = entry->next;
		}
		free(entry);
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
	// TODO: implement the lookup process here
	u8 hash_result = hash8((unsigned char *) mac, ETH_ALEN);
	//printf("get hash number %d\n", hash_result);
	mac_port_entry_t * entry_now = mac_port_map.hash_table[hash_result];
	if(!entry_now) 
		//printf("entry_now = null, find nothing\n");
		return NULL; 
	
	else {
		while(entry_now) {
			//log(DEBUG, "given mac's " ETHER_STRING " entry now 's mac " ETHER_STRING " time is %d\n",ETHER_FMT(mac), ETHER_FMT(entry_now -> mac), entry_now -> visited);
			int err = 0;
			for(int i = 0; i< ETH_ALEN; i++) {
				if (entry_now -> mac[i] == mac[i])
					continue;
				else 
					err = 1;
			}
			//printf("err = %d\n", err);
			if (err == 0){
				pthread_mutex_lock(&mac_port_map.lock);
				time(&(entry_now -> visited));
				//log(DEBUG, "find iface %s\n", entry_now -> iface -> name);
				pthread_mutex_unlock(&mac_port_map.lock);
				return entry_now ->iface;
			}
			entry_now = entry_now -> next;
		}
		//log(DEBUG, "find nothing\n");
		return NULL;
	}
	//fprintf(stdout, "TODO: implement the lookup process here.\n");
}

void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	// TODO: implement the insertion process here
	pthread_mutex_lock(&mac_port_map.lock);

	mac_port_entry_t * entry_add = (mac_port_entry_t *)malloc(sizeof(mac_port_entry_t));
	strcpy(entry_add -> mac, mac);
	entry_add -> iface = iface;
	time(&(entry_add -> visited));
	entry_add -> next = NULL;
	u8 hash_result = hash8((unsigned char *) mac, ETH_ALEN);
	//printf("hash result is %d in insert\n", hash_result);
	if (!mac_port_map.hash_table[hash_result]) {
		mac_port_map.hash_table[hash_result] = entry_add;
		//log(DEBUG, "add to first entry\n");
	}
	else {
		mac_port_entry_t * tmp = mac_port_map.hash_table[hash_result];
		while(tmp -> next)
			tmp = tmp -> next;
		tmp -> next = entry_add;
		//log(DEBUG, "add to after %s", tmp ->iface -> name);
	}

	pthread_mutex_unlock(&mac_port_map.lock);
//fprintf(stdout, "TODO: implement the insertion process here.\n");
}

void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	fprintf(stdout, "dumping the mac_port table:\n");
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		while (entry) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), \
					entry->iface->name, (int)(now - entry->visited));

			entry = entry->next;
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

int sweep_aged_mac_port_entry()
{
	time_t timenow = time(NULL);
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *tmp, *entry;
	int number = 0;
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		if (!entry) 
			continue;

		tmp = entry;
		while (tmp -> next) {
			if (timenow > tmp -> next -> visited + 30) {
				tmp -> next = tmp -> next -> next;
				free(tmp -> next);
				number ++;
				continue;
			}
			tmp = tmp -> next;
		}
		if (entry -> visited + 30 < timenow){
			mac_port_map.hash_table[i] = entry -> next;
			free(entry);
			number ++;
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	// TODO: implement the sweeping process here
	//fprintf(stdout, "TODO: implement the sweeping process here.\n");

	return number;
}

void *sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		dump_mac_port_table();
		int n = sweep_aged_mac_port_entry();

		if (n > 0)
			log(DEBUG, "%d aged entries in mac_port table are removed.\n", n);
	}

	return NULL;
}
