#include "tcp_sock.h"
#include "tcp_timer.h"
#include "log.h"

#include <unistd.h>
#include <stdio.h>

// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	file_end = 0;
	char rbuf[500];
	FILE * fp = fopen("receive.dat", "wb");
	if(!fp) {
		printf("Can't open file for write!!!\n");
		exit(1);
	}
	// int all = 0;
	while (1) {
		int rlen = tcp_sock_read(csk, rbuf, 500);
		if (rlen < 0) {
			log(DEBUG, "tcp_sock_read return negative value, finish transmission.");
			break;
		} 
		else {
			if(!rlen) {
				printf("file end\n");
				break;
			}
			// printf("read%dbyte,", rlen);
			fwrite(rbuf, 1, rlen, fp);
			// all += size;
			// printf("write %d byte to file\n", all);
			// rbuf[rlen] = '\0';
			// sprintf(wbuf, "server echoes: %s", rbuf);
			// if (tcp_sock_write(csk, wbuf, strlen(wbuf)) < 0) {
			// 	log(DEBUG, "tcp_sock_write return negative value, finish transmission.");
			// 	break;
			// }
			}
	}
	log(DEBUG, "close this connection.");
	// sleep(2);
	// tcp_sock_close(csk);
	fclose(fp);
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	FILE * fp = fopen("1MB.dat", "rb");
	if(!fp) {
		printf("Can't open file for read!!!\n");
		exit(1);
	}
	char rbuf[500];
	int size;
	while((size = fread(rbuf, 1, 500, fp))) {
		int send = tcp_sock_write(tsk, rbuf, size);
		if (send < 0) {
			printf("error send\n");
			exit(1);
		}
		usleep(5000);
	}
	while(tsk->snd_nxt != tsk->snd_una)
		sleep(1);
	sleep(1);

	// char *wbuf = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	// int wlen = strlen(wbuf);
	// char rbuf[1001];
	// int rlen = 0;

	// int n = 10;
	// for (int i = 0; i < n; i++) {
	// 	if (tcp_sock_write(tsk, wbuf + i, wlen - n) < 0)
	// 		break;

	// 	rlen = tcp_sock_read(tsk, rbuf, 1000);
	// 	if (rlen < 0) {
	// 		log(DEBUG, "tcp_sock_read return negative value, finish transmission.");
	// 		break;
	// 	}
	// 	else if (rlen > 0) {
	// 		rbuf[rlen] = '\0';
	// 		fprintf(stdout, "%s\n", rbuf);
	// 	}
	// 	else {
	// 		fprintf(stdout, "*** read data == 0.\n");
	// 	}
	// 	sleep(1);
	// }
	printf("going to relese connection\n");
	tcp_sock_close(tsk);
	fclose(fp);
	return NULL;
}
