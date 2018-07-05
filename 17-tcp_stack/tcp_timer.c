#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <unistd.h>
#include <math.h>
#include <stdio.h>

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	struct tcp_sock *tsk;
	struct tcp_timer *t, *q;
	list_for_each_entry_safe(t, q, &timer_list, list) {
		t->timeout -= SCAN_RETRAN_INTERVAL;
		// printf("timeout = %d\n", t->timeout);
		if (t->timeout <= 0) {
			list_delete_entry(&t->list);

			if(t->type == 0) {
				// only support time wait now
				tsk = timewait_to_tcp_sock(t);
				if (! tsk->parent)
					tcp_bind_unhash(tsk);
				tcp_set_state(tsk, TCP_CLOSED);
				free_tcp_sock(tsk);
			}
		}
	}
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	struct tcp_timer *timer = &tsk->timewait;

	timer->type = 0;
	timer->timeout = TCP_TIMEWAIT_TIMEOUT;
	list_add_tail(&timer->list, &timer_list);

	tcp_sock_inc_ref_cnt(tsk);
}

void handle_retrans()
{
	if(list_empty(&retrans_list)) return;
	struct tcp_timer * retrans_t = (struct tcp_timer *)(retrans_list.next);
	retrans_t->timeout -= SCAN_RETRAN_INTERVAL;
	if(retrans_t->timeout <= 0) {
		// list_delete_entry(&retrans_t->list);
		// init_list_head(&retrans_t->list);
		// printf("---------------need to send again------------------\n");
		struct tcp_sock * tsk = retrans_to_tcp_sock(retrans_t);
		struct buf_list * snd = (struct buf_list *)(tsk->snd_buf.next);
		// printf("send_head = %d, send_tail = %d, snd_num = %d\n",snd->head, snd->tail, snd->retrans_num + 1);
		if(snd->retrans_num >= 5) {
			assert(snd->retrans_num < 5);
			printf(">= 5 ci le !!!!!\n");
			// tcp_send_control_packet(tsk, TCP_RST);
			tcp_sock_close(tsk);
			list_delete_entry(&retrans_t->list);
			init_list_head(&retrans_t->list);
			return;
		}
		char * snd_data = malloc(snd->len);
		memcpy(snd_data, snd->data, snd->len);
		ip_send_packet(snd_data, snd->len);
		// printf("send sucessfully, snd _num = %d\n", snd->retrans_num + 1);
		snd->retrans_num += 1;
		retrans_t->timeout = (1 << snd->retrans_num) * RETRAN_TIME;
		// printf("timeout = %d\n", retrans_t->timeout);

	}
}
// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);

	while (1) {
		usleep(SCAN_RETRAN_INTERVAL);
		tcp_scan_timer_list();
		handle_retrans();
	}

	return NULL;
}
//---------------------------------------------

void tcp_set_retrans_timer(struct tcp_sock *tsk)
{
	struct tcp_timer *timer = &tsk->retrans_timer;
	
	timer->type = 1;//retrans_timer
	timer->timeout = RETRAN_TIME;
	list_add_tail(&timer->list, &retrans_list);
	// tcp_sock_inc_ref_cnt(tsk);
}

//----------------------------------------------
