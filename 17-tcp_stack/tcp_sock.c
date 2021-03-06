#include "tcp.h"
#include "tcp_hash.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "ip.h"
#include "rtable.h"
#include "log.h"

// TCP socks should be hashed into table for later lookup: Those which
// occupy a port (either by *bind* or *connect*) should be hashed into
// bind_table, those which listen for incoming connection request should be
// hashed into listen_table, and those of established connections should
// be hashed into established_table.

struct tcp_hash_table tcp_sock_table;
#define tcp_established_sock_table	tcp_sock_table.established_table
#define tcp_listen_sock_table		tcp_sock_table.listen_table
#define tcp_bind_sock_table			tcp_sock_table.bind_table

inline void tcp_set_state(struct tcp_sock *tsk, int state)
{
	log(DEBUG, IP_FMT":%hu switch state, from %s to %s.", \
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport, \
			tcp_state_str[tsk->state], tcp_state_str[state]);
	tsk->state = state;
}

// init tcp hash table and tcp timer
void init_tcp_stack()
{
	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_established_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_listen_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_bind_sock_table[i]);

	pthread_t timer;
	pthread_create(&timer, NULL, tcp_timer_thread, NULL);
}

// allocate tcp sock, and initialize all the variables that can be determined
// now
struct tcp_sock *alloc_tcp_sock()
{
	struct tcp_sock *tsk = malloc(sizeof(struct tcp_sock));

	memset(tsk, 0, sizeof(struct tcp_sock));

	tsk->state = TCP_CLOSED;
	tsk->rcv_wnd = TCP_DEFAULT_WINDOW;

	init_list_head(&tsk->list);
	init_list_head(&tsk->listen_queue);
	init_list_head(&tsk->accept_queue);
	init_list_head(&tsk->snd_buf);
	init_list_head(&tsk->rcv_ofo_buf);
	init_list_head(&(tsk->retrans_timer.list));
	init_list_head(&retrans_list);

	tsk->rcv_buf = alloc_ring_buffer(tsk->rcv_wnd);
	tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
	tsk->wait_connect = alloc_wait_struct();
	tsk->wait_accept = alloc_wait_struct();
	tsk->wait_recv = alloc_wait_struct();
	tsk->wait_send = alloc_wait_struct();

	return tsk;
}

// release all the resources of tcp sock
//
// To make the stack run safely, each time the tcp sock is refered (e.g. hashed), 
// the ref_cnt is increased by 1. each time free_tcp_sock is called, the ref_cnt
// is decreased by 1, and release the resources practically if ref_cnt is
// decreased to zero.
void free_tcp_sock(struct tcp_sock *tsk)
{
	tsk->ref_cnt -= 1;
	if (tsk->ref_cnt <= 0) {
		log(DEBUG, "free tcp sock: ["IP_FMT":%hu<->"IP_FMT":%hu].", \
				HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport,
				HOST_IP_FMT_STR(tsk->sk_dip), tsk->sk_dport);

		free_wait_struct(tsk->wait_connect);
		free_wait_struct(tsk->wait_accept);
		free_wait_struct(tsk->wait_recv);
		free_wait_struct(tsk->wait_send);

		free_ring_buffer(tsk->rcv_buf);

		free(tsk);
	}
}

// lookup tcp sock in established_table with key (saddr, daddr, sport, dport)
struct tcp_sock *tcp_sock_lookup_established(u32 saddr, u32 daddr, u16 sport, u16 dport)
{
	// fprintf(stdout, "TODO: implement this function please.\n");
	int value = tcp_hash_function(saddr, daddr, sport, dport);
	struct list_head *list= &tcp_established_sock_table[value];
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, hash_list) {
		if(tsk->sk_sip == saddr && tsk->sk_sport == sport && \
			tsk->sk_dip == daddr && tsk->sk_dport == dport)
			return tsk;
	}
	return NULL;
}

// lookup tcp sock in listen_table with key (sport)
//
// In accordance with BSD socket, saddr is in the argument list, but never used.
struct tcp_sock *tcp_sock_lookup_listen(u32 saddr, u16 sport)
{
	// fprintf(stdout, "TODO: implement this function please.\n");
	int value = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list= &tcp_listen_sock_table[value];
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, hash_list) {
		if(tsk->sk_sport == sport)
			return tsk;
	}

	return NULL;
}

// lookup tcp sock in both established_table and listen_table
struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb)
{
	u32 saddr = cb->daddr,
		daddr = cb->saddr;
	u16 sport = cb->dport,
		dport = cb->sport;
	// printf("port = %hu\n", sport);
	struct tcp_sock *tsk = tcp_sock_lookup_established(saddr, daddr, sport, dport);
	if (!tsk)
		tsk = tcp_sock_lookup_listen(saddr, sport);
	// if(tsk) 
	 	// log(DEBUG, "find "IP_FMT":%hu, state =  %s", HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport, tcp_state_str[tsk->state]);
	return tsk;
}

// hash tcp sock into bind_table, using sport as the key
static int tcp_bind_hash(struct tcp_sock *tsk)
{
	int bind_hash_value = tcp_hash_function(0, 0, tsk->sk_sport, 0);
	struct list_head *list = &tcp_bind_sock_table[bind_hash_value];
	list_add_head(&tsk->bind_hash_list, list);

	tcp_sock_inc_ref_cnt(tsk);

	return 0;
}

// unhash the tcp sock from bind_table
void tcp_bind_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->bind_hash_list)) {
		list_delete_entry(&tsk->bind_hash_list);
		free_tcp_sock(tsk);
	}
}

// lookup bind_table to check whether sport is in use
static int tcp_port_in_use(u16 sport)
{
	int value = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_bind_sock_table[value];
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, hash_list) {
		if (tsk->sk_sport == sport)
			return 1;
	}

	return 0;
}

// find a free port by looking up bind_table
static u16 tcp_get_port()
{
	for (u16 port = PORT_MIN; port < PORT_MAX; port++) {
		if (!tcp_port_in_use(port))
			return port;
	}

	return 0;
}

// tcp sock tries to use port as its source port
static int tcp_sock_set_sport(struct tcp_sock *tsk, u16 port)
{
	if ((port && tcp_port_in_use(port)) ||
			(!port && !(port = tcp_get_port())))
		return -1;

	tsk->sk_sport = port;

	tcp_bind_hash(tsk);

	return 0;
}

// hash tcp sock into either established_table or listen_table according to its
// TCP_STATE
int tcp_hash(struct tcp_sock *tsk)
{
	struct list_head *list;
	int hash;

	if (tsk->state == TCP_CLOSED)
		return -1;

	if (tsk->state == TCP_LISTEN) {
		hash = tcp_hash_function(0, 0, tsk->sk_sport, 0);
		list = &tcp_listen_sock_table[hash];
	}
	else {
		int hash = tcp_hash_function(tsk->sk_sip, tsk->sk_dip, \
				tsk->sk_sport, tsk->sk_dport); 
		list = &tcp_established_sock_table[hash];

		struct tcp_sock *tmp;
		list_for_each_entry(tmp, list, hash_list) {
			if (tsk->sk_sip == tmp->sk_sip &&
					tsk->sk_dip == tmp->sk_dip &&
					tsk->sk_sport == tmp->sk_sport &&
					tsk->sk_dport == tmp->sk_dport)
				return -1;
		}
	}

	list_add_head(&tsk->hash_list, list);
	tcp_sock_inc_ref_cnt(tsk);

	return 0;
}

// unhash tcp sock from established_table or listen_table
void tcp_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->hash_list)) {
		list_delete_entry(&tsk->hash_list);
		free_tcp_sock(tsk);
	}
}

// XXX: skaddr here contains network-order variables
int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	int err = 0;

	// omit the ip address, and only bind the port
	err = tcp_sock_set_sport(tsk, ntohs(skaddr->port));

	return err;
}

// connect to the remote tcp sock specified by skaddr
//
// XXX: skaddr here contains network-order variables
// 1. initialize the four key tuple (sip, sport, dip, dport);
// 2. hash the tcp sock into bind_table;
// 3. send SYN packet, switch to TCP_SYN_SENT state, wait for the incoming
//    SYN packet by sleep on wait_connect;
// 4. if the SYN packet of the peer arrives, this function is notified, which
//    means the connection is established.
int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	// fprintf(stdout, "TODO: implement this function please.\n");
	// 1
	tsk->sk_sip = ((iface_info_t *)(instance->iface_list.next))->ip;
	tcp_sock_set_sport(tsk,tcp_get_port());
	tsk->sk_dip = ntohl(skaddr->ip);
	tsk->sk_dport = ntohs(skaddr->port);
	// 2 already done
	// tcp_bind_hash(tsk);
	//3
	tsk->snd_nxt = tcp_new_iss();
	tcp_set_state(tsk, TCP_SYN_SENT);
	tcp_hash(tsk);
	tcp_send_control_packet(tsk, TCP_SYN);
	sleep_on(tsk->wait_connect);
	// tcp_set_state(tsk, TCP_ESTABLISHED);
	return 1;
}

// set backlog (the maximum number of pending connection requst), switch the
// TCP_STATE, and hash the tcp sock into listen_table
int tcp_sock_listen(struct tcp_sock *tsk, int backlog)
{
	// fprintf(stdout, "TODO: implement this function please.\n");
	tsk->backlog = backlog;
	tcp_set_state(tsk, TCP_LISTEN);
	int value = tcp_hash_function(0, 0, tsk->sk_sport, 0);
	struct list_head *list= &tcp_listen_sock_table[value];
	list_add_head(&tsk->hash_list, list);	
	return 1;
}

// check whether the accept queue is full
inline int tcp_sock_accept_queue_full(struct tcp_sock *tsk)
{
	if (tsk->accept_backlog >= tsk->backlog) {
		log(ERROR, "tcp accept queue (%d) is full.", tsk->accept_backlog);
		return 1;
	}

	return 0;
}

// push the tcp sock into accept_queue
inline void tcp_sock_accept_enqueue(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->list))
		list_delete_entry(&tsk->list);
	list_add_tail(&tsk->list, &tsk->parent->accept_queue);
	tsk->parent->accept_backlog += 1;
}

// pop the first tcp sock of the accept_queue
inline struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk)
{
	struct tcp_sock *new_tsk = list_entry(tsk->accept_queue.next, struct tcp_sock, list);
	list_delete_entry(&new_tsk->list);
	init_list_head(&new_tsk->list);
	tsk->accept_backlog -= 1;

	return new_tsk;
}

// if accept_queue is not emtpy, pop the first tcp sock and accept it,
// otherwise, sleep on the wait_accept for the incoming connection requests
struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement this function please.\n");
	if(list_empty(&tsk->accept_queue)) 
		sleep_on(tsk->wait_accept);
	struct tcp_sock *accept_child = tcp_sock_accept_dequeue(tsk);
	tcp_set_state(accept_child, TCP_ESTABLISHED);
	return accept_child;
}

// clear the listen queue, which is carried out when *close* the tcp sock
static void tcp_sock_clear_listen_queue(struct tcp_sock *tsk)
{
	struct tcp_sock *lsn_tsk;
	while (!list_empty(&tsk->listen_queue)) {
		lsn_tsk = list_entry(tsk->listen_queue.next, struct tcp_sock, list);
		list_delete_entry(&lsn_tsk->list);

		if (lsn_tsk->state == TCP_SYN_RECV) {
			lsn_tsk->parent = NULL;
			tcp_unhash(lsn_tsk);
			free_tcp_sock(lsn_tsk);
		}
	}
}

// close the tcp sock, by releasing the resources, sending FIN/RST packet
// to the peer, switching TCP_STATE to closed
void tcp_sock_close(struct tcp_sock *tsk)
{
	switch (tsk->state) {
		case TCP_CLOSED:
			break;
		case TCP_LISTEN:
			tcp_sock_clear_listen_queue(tsk);
			tcp_unhash(tsk);
			tcp_set_state(tsk, TCP_CLOSED);
			break;
		case TCP_SYN_RECV:
			break;
		case TCP_SYN_SENT:
			break;
		case TCP_ESTABLISHED:
			tcp_send_control_packet(tsk, TCP_FIN|TCP_ACK);
			tcp_set_state(tsk, TCP_FIN_WAIT_1);
			break;
		case TCP_CLOSE_WAIT:
			tcp_send_control_packet(tsk, TCP_FIN|TCP_ACK);
			tcp_set_state(tsk, TCP_LAST_ACK);
			break;
	}
}

int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len)
{
	struct ring_buffer * rbf = tsk->rcv_buf;
	// if(ring_buffer_empty(rbf)) 
	// 	sleep_on(tsk->wait_recv);
	while(ring_buffer_empty(rbf) && !file_end)
		usleep(100);
	pthread_mutex_lock(&tsk->wait_send->lock);
	int read_len = read_ring_buffer(rbf, buf, len);
	pthread_mutex_unlock(&tsk->wait_send->lock);
	assert(read_len > 0 || file_end);
	// int ring_wnd = ring_buffer_free(rbf);
	// if(ring_wnd < tsk->rcv_wnd)
	// 	tsk->rcv_wnd = ring_wnd;
	return read_len;
}

int tcp_sock_write(struct tcp_sock *tsk, char *buf, int len)
{
	// printf("wnd = %d\n",tsk->snd_wnd);
	int packet_len = min(len + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE, ETH_FRAME_LEN);
	while(tsk->snd_wnd < packet_len) {
		// printf("wnd <<<<<<<<<<<<<<<<<<<\n");
		usleep(1000);
	}
	char * packet = malloc(packet_len);
	char * data = packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	memcpy(data, buf, packet_len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE);
	if(tsk->snd_wnd >= packet_len) {
		tcp_send_packet(tsk, packet, packet_len);
		return packet_len;
	}
	// printf("not send ???,wnd = %d, len=%d\n",tsk->snd_wnd, packet_len );
	return 0;
}

void pend2buf(struct tcp_sock *tsk, u32 head, u32 tail, char * data, int len)
{
	struct buf_list * buf = malloc(sizeof(struct buf_list));
	buf->head = head;
	buf->tail = tail;
	buf->data = malloc(len);
	buf->retrans_num = 0;
	buf->len = len;
	memcpy(buf->data, data, len);
	list_add_tail(&buf->list, &tsk->snd_buf);
	// struct buf_list * entry;
	// int num = 0;
	// list_for_each_entry(entry, &tsk->snd_buf, list)
	// 	num++;
	// printf("add a send buf, now num is %d\n", num);
	if(list_empty(&(tsk->retrans_timer.list))) {
		// printf("add timer\n");
		tcp_set_retrans_timer(tsk);
	}
	// printf("timeout is %d", ((struct tcp_timer *)(retrans_list.next))->timeout);
}

void relese_snd_buf(struct tcp_sock *tsk, u32 ack)
{
	if(ack <= tsk->snd_una) return;
	struct buf_list *entry, *q;
	// printf("remove seq_end <= %d\n", ack);
	list_for_each_entry_safe(entry, q, &tsk->snd_buf, list) {
		if(entry->tail <= ack) {
			list_delete_entry(&entry->list);
			free(entry);
		}
	}
	if(ack < tsk->snd_nxt) {
		// printf("still thing to be ack\n");
		tsk->retrans_timer.timeout = RETRAN_TIME;
	}
	if(ack >= tsk->snd_nxt) {
		// printf("delete timer, ack=%d, snd_nxt = %d\n", ack, tsk->snd_nxt);
		struct tcp_timer * tm = &tsk->retrans_timer;
		list_delete_entry(&tm->list);
		init_list_head(&tm->list);
	}
}

void move2ring(struct tcp_sock *tsk, struct buf_list * buf)//
{
	// printf("in move2ring, buf->head = %d, rcv_nxt = %d\n",buf->head, tsk->rcv_nxt );
	// if(tsk->rcv_nxt == buf->head) {
		pthread_mutex_lock(&tsk->wait_send->lock);
		write_ring_buffer(tsk->rcv_buf, buf->data, buf->len);
		pthread_mutex_unlock(&tsk->wait_send->lock);
		// printf("movetoringhead=%d,tail=%d ", buf->head,buf->tail);
		tsk->rcv_nxt = buf->tail;
		list_delete_entry(&buf->list);
		free(buf);
		// wake_up(tsk->wait_recv);
		// if(!ring_buffer_full(tsk->rcv_buf)){
		// 	int find = 0;
		// 	list_for_each_entry_safe(entry, q, &tsk->rcv_ofo_buf, list) 
		// 		if(entry->head == tsk->rcv_nxt){
		// 			find = 1;
		// 			break;
		// 		}
		// 	if(find && ring_buffer_free(tsk->rcv_buf) >= entry->len)
		// 		move2ring(tsk, entry);
		// }
		// return 1;
	// }
	// return 0;
}

void reserve(struct tcp_sock *tsk, u32 head, u32 tail, char *data, int len, int trigger)
{
	struct buf_list * entry;
	list_for_each_entry(entry, &tsk->rcv_ofo_buf, list) {
		if(entry->head == head && entry->tail == tail){
		 	printf("reveive same packet!!!!!!!!!!!!!!!!\n");
			return;
		}
	}
	if(trigger == 0) {
		struct buf_list * buf = malloc(sizeof(struct buf_list));
		buf->head = head;
		buf->tail = tail;
		buf->data = malloc(len);
		buf->retrans_num = 0; //not used here
		buf->len = len;
		memcpy(buf->data, data, len);
		// printf("pend a packet in receiving buffer\n");
		list_add_tail(&buf->list, &tsk->rcv_ofo_buf);
	}
	else {

		// printf("list head\n");
		// struct buf_list * pp;
		// list_for_each_entry(pp, &tsk->rcv_ofo_buf, list) 
		// 	printf("%d ",  pp->head);

		// assert(ring_buffer_free(tsk->rcv_buf) > buf->len);
		pthread_mutex_lock(&tsk->wait_send->lock);
		write_ring_buffer(tsk->rcv_buf, data, len);
		pthread_mutex_unlock(&tsk->wait_send->lock);
		// printf("movetoringhead=%d,tail=%d ",head,tail);
		// wake_up(tsk->wait_recv);
		int find = 1;	
		while(find) {
			find = 0;
			struct buf_list *entry, *q;
			list_for_each_entry_safe(entry, q, &tsk->rcv_ofo_buf, list) {
				if(entry->head == tsk->rcv_nxt) {
					// if(ring_buffer_free(tsk->rcv_buf) >= entry->len){
						move2ring(tsk,entry);
						find = 1;					
						break;
					// }
					// else
					// 	printf("--------------------------ring buffer full---------------\n");
				}
			}
		}
	}
}