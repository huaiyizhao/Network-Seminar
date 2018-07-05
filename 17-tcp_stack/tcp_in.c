#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
#include <unistd.h>
// handling incoming packet for TCP_LISTEN state
//
// 1. malloc a child tcp sock to serve this connection request; 
// 2. send TCP_SYN | TCP_ACK by child tcp sock;
// 3. hash the child tcp sock into established_table (because the 4-tuple 
//    is determined).
void tcp_state_listen(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	if(!(cb->flags & TCP_SYN)) 
		if(!(cb->flags & TCP_RST)){
			tcp_send_reset(cb); 
			return;
		}
	//1
	struct tcp_sock *child_sk = alloc_tcp_sock();
	child_sk->parent = tsk;
	child_sk->sk_sip = cb->daddr;
	child_sk->sk_dip = cb->saddr;
	child_sk->sk_sport = cb->dport;
	child_sk->sk_dport = cb->sport;
	child_sk->rcv_nxt = cb->seq_end;
	child_sk->snd_nxt = tcp_new_iss();
	struct sock_addr skaddr = {htonl(child_sk->sk_sip), htons(child_sk->sk_sport)};
	tcp_sock_bind(child_sk, &skaddr);
	list_add_tail(&child_sk->list, &tsk->listen_queue);
	//2
	tcp_send_control_packet(child_sk, TCP_SYN | TCP_ACK);
	//3
	tcp_set_state(child_sk, TCP_SYN_RECV);
	tcp_hash(child_sk);
	// fprintf(stdout, "TODO: implement this function please.\n");
}

// handling incoming packet for TCP_CLOSED state, by replying TCP_RST
void tcp_state_closed(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	tcp_send_reset(cb);
}

// handling incoming packet for TCP_SYN_SENT state
//
// If everything goes well (the incoming packet is TCP_SYN|TCP_ACK), reply with 
// TCP_ACK, and enter TCP_ESTABLISHED state, notify tcp_sock_connect; otherwise, 
// reply with TCP_RST.
void tcp_state_syn_sent(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	// fprintf(stdout, "TODO: implement this function please.\n");
	// reply
	if(!( (cb->flags & TCP_SYN) && (cb->flags & TCP_ACK) ) ) {tcp_send_reset(cb); return;}
	tsk->rcv_nxt = cb->seq_end;
	tsk->snd_una = cb->ack;
	tsk->snd_wnd = cb->rwnd;
	tcp_send_control_packet(tsk, TCP_ACK);
	//established
	tcp_set_state(tsk, TCP_ESTABLISHED);
	tcp_hash(tsk);
	// notify
	wake_up(tsk->wait_connect);
}

// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

// handling incoming ack packet for tcp sock in TCP_SYN_RECV state
//
// 1. remove itself from parent's listen queue;
// 2. add itself to parent's accept queue;
// 3. wake up parent (wait_accept) since there is established connection in the
//    queue.
void tcp_state_syn_recv(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	// fprintf(stdout, "TODO: implement this function please.\n");
	// assert(cb->state & TCP_ACK);
	//1 2 
	tcp_sock_accept_enqueue(tsk);
	// tsk->rcv_nxt = cb->seq_end;
	// tsk->snd_una = cb->ack;
	tsk->snd_wnd = cb->rwnd;
	//3
	wake_up(tsk->parent->wait_accept);
	usleep(1000);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.")
		log(ERROR, "cb->seq = %d, cb->seq_end = %d, tsk->rcv_nxt = %d, rcv_end = %d",
			cb->seq, cb->seq_end, tsk->rcv_nxt, rcv_end);
		return 0;
	}
}

// Process an incoming packet as follows:
// 	 1. if the state is TCP_CLOSED, hand the packet over to tcp_state_closed;
// 	 2. if the state is TCP_LISTEN, hand it over to tcp_state_listen;
// 	 3. if the state is TCP_SYN_SENT, hand it to tcp_state_syn_sent;
// 	 4. check whether the sequence number of the packet is valid, if not, drop
// 	    it;
// 	 5. if the TCP_RST bit of the packet is set, close this connection, and
// 	    release the resources of this tcp sock;
// 	 6. if the TCP_SYN bit is set, reply with TCP_RST and close this connection,
// 	    as valid TCP_SYN has been processed in step 2 & 3;
// 	 7. check if the TCP_ACK bit is set, since every packet (except the first 
//      SYN) should set this bit;
//   8. process the ack of the packet: if it ACKs the outgoing SYN packet, 
//      establish the connection; (if it ACKs new data, update the window;)
//      if it ACKs the outgoing FIN packet, switch to correpsonding state;
//   9. (process the payload of the packet: call tcp_recv_data to receive data;)
//  10. if the TCP_FIN bit is set, update the TCP_STATE accordingly;
//  11. at last, do not forget to reply with TCP_ACK if the connection is alive.
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	log(DEBUG, "receive packet: flag = %x,seq = %d,ack = %d", 
		cb->flags, cb->seq, cb->ack);
	relese_snd_buf(tsk, cb->ack);
	int trigger = 0;
	// assert(tsk->rcv_nxt == 0 || cb->seq == tsk->rcv_nxt);
	if(cb->seq == tsk->rcv_nxt && tsk->rcv_nxt != 0) {
		trigger = 1;
		tsk->rcv_nxt = cb->seq_end;
	}
	else if(tsk->rcv_nxt == 0) 
		tsk->rcv_nxt = cb->seq_end;
	tsk->snd_una = cb->ack;
	tcp_update_window_safe(tsk, cb);
	if(cb->flags & TCP_RST) {tcp_set_state(tsk, TCP_CLOSED); tcp_unhash(tsk); return;}
	int state = tsk->state;
	switch(state) {
		case TCP_CLOSED :
			tcp_state_closed(tsk, cb, packet);
			break;
		case TCP_LISTEN :
			tcp_state_listen(tsk, cb, packet);
			break;
		case TCP_SYN_SENT :
			tcp_state_syn_sent(tsk, cb, packet);
			break;
		case TCP_SYN_RECV :
			tcp_state_syn_recv(tsk, cb, packet); 
			break;
		case TCP_FIN_WAIT_1 :
			if(cb->ack == tsk->snd_nxt)
				tcp_set_state(tsk, TCP_FIN_WAIT_2);
			break;
		case TCP_FIN_WAIT_2 :
			if(cb->flags & TCP_FIN && cb->ack == tsk->snd_nxt) {
					tcp_set_state(tsk, TCP_TIME_WAIT); 
				tcp_set_timewait_timer(tsk);
				tcp_send_control_packet(tsk, TCP_ACK);
			}
			break;
		case TCP_CLOSE_WAIT :
			if(cb->flags & TCP_FIN)// ACK packet loss
				tcp_send_control_packet(tsk, TCP_ACK);
			break;
		case TCP_TIME_WAIT :
			if(cb->flags == TCP_FIN + TCP_ACK) 
				tcp_send_control_packet(tsk, TCP_ACK);
			break;
		case TCP_LAST_ACK :
			if(cb->flags == TCP_ACK && cb->ack == tsk->snd_nxt)
				tcp_set_state(tsk,TCP_CLOSED);
			break;
		case TCP_ESTABLISHED :
			if(cb->flags & TCP_FIN && cb->ack == tsk->snd_nxt) {
				tcp_set_state(tsk, TCP_CLOSE_WAIT);
				tcp_send_control_packet(tsk, TCP_ACK);
				while(!ring_buffer_empty(tsk->rcv_buf))
					sleep(1);
				tcp_sock_close(tsk);
			}
			else if(cb->pl_len) {// pend packet
				// printf("go to reserve\n");
				reserve(tsk, cb->seq, cb->seq_end, cb->payload, cb->pl_len, trigger);
				// tsk->rcv_wnd = TCP_DEFAULT_WINDOW + tsk->rcv_nxt - cb->seq_end;
				tcp_send_control_packet(tsk,TCP_ACK); 
			}
			else if(cb->flags == TCP_ACK && cb->pl_len == 0) ;// avoid ACK loop
			else
				tcp_send_control_packet(tsk,TCP_ACK); 

			break;
		default:
			;
	}

	// //below is a bad implementation
	// log(DEBUG, "receive packet: flag = %x,seq = %d,ack = %d,tsk->rcv_nxt = %d", 
	// 	cb->flags, cb->seq, cb->ack, tsk->rcv_nxt);
	// // assert(cb->ack <= tsk->snd_nxt);
	// relese_snd_buf(tsk, cb->ack);
	// int state = tsk->state;
	// if(state == TCP_CLOSED) {tcp_state_closed(tsk, cb, packet); return;}//1
	// if(state == TCP_LISTEN) {tcp_state_listen(tsk, cb, packet); return;}//2
	// if(state == TCP_SYN_SENT) {tcp_state_syn_sent(tsk, cb, packet); return;}//3
	
	// // if(!is_tcp_seq_valid(tsk,cb)) return;//4
	// if(cb->flags & TCP_RST) {tcp_set_state(tsk, TCP_CLOSED); tcp_unhash(tsk); return;}//5
	// // if(cb->flags & TCP_SYN) {tcp_send_reset(cb); tcp_set_state(tsk, TCP_CLOSED); return;}//6
	// //7
	// if(!(cb->flags & TCP_ACK)) {
	// 	tcp_send_reset(cb);
	// 	return;
	// }
	// //all below has a ACK
	// tcp_update_window_safe(tsk, cb);
	// tsk->snd_una = cb->ack;
	// if(cb->seq <= tsk->rcv_nxt && cb->seq_end > tsk->rcv_nxt)
	// 	tsk->rcv_nxt = cb->seq_end;
	// //8
	// //syn-rcvd
	// if((state == TCP_SYN_RECV) && (cb->ack >= tsk->snd_nxt)) {
	// 	printf("in syn recv\n");
	// 	tcp_state_syn_recv(tsk, cb, packet); 
	// 	return;
	// }
	// //fin-wait-1
	// if((state == TCP_FIN_WAIT_1) && (cb->ack == tsk->snd_nxt)) {
	// 	tcp_set_state(tsk, TCP_FIN_WAIT_2);
	// 	return;
	// }
	// //fin-wait-2
	// if((cb->flags & TCP_FIN) && (state == TCP_FIN_WAIT_2)) {
	// 	tcp_set_state(tsk, TCP_TIME_WAIT); 
	// 	tcp_set_timewait_timer(tsk);
	// 	tcp_send_control_packet(tsk, TCP_ACK); 
	// 	return;
	// }
	// //last ack
	// if((state == TCP_LAST_ACK) && (cb->ack == tsk->snd_nxt)) {
	// 	tcp_set_state(tsk, TCP_CLOSED);
	// 	return;
	// }
	// // request fin
	// if((cb->flags & TCP_FIN) && (state == TCP_ESTABLISHED)) {
	// 	tcp_set_state(tsk, TCP_CLOSE_WAIT); 
	// 	tcp_send_control_packet(tsk, TCP_ACK);
	// 	return;
	// 	// sleep(1);
	// 	// tcp_sock_close(tsk);
	// }
	// if((state == TCP_CLOSE_WAIT) && (cb->flags & TCP_FIN)){// ACK packet loss
	// 	tcp_send_control_packet(tsk, TCP_ACK);
	// 	return;
	// }
	// if((state == TCP_TIME_WAIT) && (cb->flags == TCP_FIN + TCP_ACK)) {
	// 	tcp_send_control_packet(tsk, TCP_ACK);
	// 	return;
	// }

	// //normal
	// if(state == TCP_ESTABLISHED) {
	// 	// printf("???\n");
	// 	assert(cb->flags == TCP_ACK || cb->flags == TCP_ACK + TCP_PSH || cb->flags == TCP_ACK + TCP_SYN);
	// 	// printf("receive a ack packet");
	// 	if(cb->flags == TCP_ACK && cb->pl_len == 0) return;// avoid ACK loop
	// 	if(cb->pl_len) {
	// 		if(cb->seq >= tsk->rcv_nxt) { // some packet missing
	// 			printf("go to reserve\n");
	// 			reserve(tsk, cb->seq, cb->seq_end, cb->payload, cb->pl_len);
	// 		}
	// 		// else if(tsk->rcv_nxt == cb->seq){// get the right packet !!rcv_nxt had been set
	// 		// 	write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
	// 		// 	wake_up(tsk->wait_recv);
	// 		// }
	// 		else ; // old packet
	// 		tsk->rcv_wnd = TCP_DEFAULT_WINDOW + tsk->rcv_nxt - cb->seq_end;
	// 		tcp_send_control_packet(tsk,TCP_ACK); 
	// 		return;
	// 	}
	// 	printf("may happen sometime\n");
	// 	tcp_send_control_packet(tsk,TCP_ACK); 
	// 	// wake_up(tsk->wait_send);
	// }
}
