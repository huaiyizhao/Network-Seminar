#ifndef __TCP_TIMER_H__
#define __TCP_TIMER_H__

#include "list.h"

#include <stddef.h>
struct list_head timer_list;
struct list_head retrans_list;

struct tcp_timer {
	struct list_head list;
	int type;	// now only support time-wait
	int timeout;	// in micro second
};

struct tcp_sock;
#define timewait_to_tcp_sock(t) \
	(struct tcp_sock *)((char *)(t) - offsetof(struct tcp_sock, timewait))
#define retrans_to_tcp_sock(t) \
	(struct tcp_sock *)((char *)(t) - offsetof(struct tcp_sock, retrans_timer))

#define TCP_TIMER_SCAN_INTERVAL 100000
#define TCP_MSL			1000000
#define TCP_TIMEWAIT_TIMEOUT	(2 * TCP_MSL)
//for reliable transportation
#define SCAN_RETRAN_INTERVAL 10000 //10ms
#define RETRAN_TIME 200000 //200ms

// the thread that scans timer_list periodically
void *tcp_timer_thread(void *arg);
// add the timer of tcp sock to timer_list
void tcp_set_timewait_timer(struct tcp_sock *);

// add the retrans_timer to timer_list
void tcp_set_retrans_timer(struct tcp_sock *);
#endif
