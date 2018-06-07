/* client application */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
 
int main(int argc, char *argv[])
{
    int sock1, sock2;
    struct sockaddr_in server1, server2;
    uint32_t len1, len2;
    char pwd[100];
    strcpy(pwd,argv[1]);
    uint32_t file_len;
    uint32_t worker1_reply[26], worker2_reply[26];
    
    FILE* fp;
    fp = fopen(pwd, "rb");
    fseek(fp,0,SEEK_END);
    file_len = ftell(fp);
    // printf("file length = %d\n", file_len);
    fclose(fp);
    //Create socket
    sock1 = socket(AF_INET, SOCK_STREAM, 0);
    sock2 = socket(AF_INET, SOCK_STREAM, 0);
    if (sock1 == -1 || sock2 == -1) {
        printf("Could not create socket");
    }
    printf("Socket created");
     
    FILE * addr = fopen("workers.conf", "rb");
    char ipaddr1[15], ipaddr2[15];
    fgets(ipaddr1, 16, addr);
    fgets(ipaddr2, 16, addr);

    server1.sin_addr.s_addr = inet_addr(ipaddr1);
    server1.sin_family = AF_INET;
    server1.sin_port = htons( 12345 );
    server2.sin_addr.s_addr = inet_addr(ipaddr2);
    server2.sin_family = AF_INET;
    server2.sin_port = htons( 12345 );
 
    //Connect to remote server
    if (connect(sock1, (struct sockaddr *)&server1, sizeof(server1)) < 0) {
        perror("connect 1 failed. Error");
        return 1;
    }
    if (connect(sock2, (struct sockaddr *)&server2, sizeof(server2)) < 0) {
	perror("connect 2 failed. Error");
	return 1;
    }
     
    printf("Connected\n");
     

	//send data
    len1 = strlen(pwd) + 12;
	len2 = len1;
	uint32_t net_len1 = htonl(len1);
	uint32_t net_len2 = htonl(len2);
    // printf("len1 = %d, net_len1 = %d\n", len1, net_len1);
    if (send(sock1, &net_len1, 4, 0) < 0 || send(sock2, &net_len2, 4, 0) < 0) {
        printf("Send message length failed");
        return 1;
    }
    // printf("send length success\n");
    if (send(sock1, pwd, strlen(pwd), 0) < 0 || send(sock2, pwd, strlen(pwd), 0) < 0) {
	    printf("Send pwd failed");
	    return 1;
	}
    // printf("send pwd success\n");
	uint32_t net_begin = htonl(0);
	uint32_t net_middle = htonl(file_len / 2);
	uint32_t net_end = htonl(file_len);
	if (send(sock1, &net_begin, 4, 0) < 0 || send(sock2, &net_middle, 4, 0) < 0 || send(sock1, &net_middle, 4, 0) < 0 || send(sock2, &net_end, 4, 0) < 0) {
	    printf("Send boundary failed");
	    return 1;
	} 

    //Receive result
    if (recv(sock1, worker1_reply, 104, 0) < 0 || recv(sock2, worker2_reply, 104, 0) < 0) {
        printf("recv failed");
        return 1;
    }
         
	printf("a %d\n", ntohl(worker1_reply[0]) + ntohl(worker2_reply[0]) );
    printf("b %d\n", ntohl(worker1_reply[1]) + ntohl(worker2_reply[1]) );
    printf("c %d\n", ntohl(worker1_reply[2]) + ntohl(worker2_reply[2]) );
    printf("d %d\n", ntohl(worker1_reply[3]) + ntohl(worker2_reply[3]) );
    printf("e %d\n", ntohl(worker1_reply[4]) + ntohl(worker2_reply[4]) );
    printf("f %d\n", ntohl(worker1_reply[5]) + ntohl(worker2_reply[5]) );
    printf("g %d\n", ntohl(worker1_reply[6]) + ntohl(worker2_reply[6]) );
    printf("h %d\n", ntohl(worker1_reply[7]) + ntohl(worker2_reply[7]) );
    printf("i %d\n", ntohl(worker1_reply[8]) + ntohl(worker2_reply[8]) );
    printf("j %d\n", ntohl(worker1_reply[9]) + ntohl(worker2_reply[9]) );
    printf("k %d\n", ntohl(worker1_reply[10]) + ntohl(worker2_reply[10]) );
    printf("l %d\n", ntohl(worker1_reply[11]) + ntohl(worker2_reply[11]) );
    printf("m %d\n", ntohl(worker1_reply[12]) + ntohl(worker2_reply[12]) );
    printf("n %d\n", ntohl(worker1_reply[13]) + ntohl(worker2_reply[13]) );
    printf("o %d\n", ntohl(worker1_reply[14]) + ntohl(worker2_reply[14]) );
    printf("p %d\n", ntohl(worker1_reply[15]) + ntohl(worker2_reply[15]) );
    printf("q %d\n", ntohl(worker1_reply[16]) + ntohl(worker2_reply[16]) );
    printf("r %d\n", ntohl(worker1_reply[17]) + ntohl(worker2_reply[17]) );
    printf("s %d\n", ntohl(worker1_reply[18]) + ntohl(worker2_reply[18]) );
    printf("t %d\n", ntohl(worker1_reply[19]) + ntohl(worker2_reply[19]) );
    printf("u %d\n", ntohl(worker1_reply[20]) + ntohl(worker2_reply[20]) );
    printf("v %d\n", ntohl(worker1_reply[21]) + ntohl(worker2_reply[21]) );
    printf("w %d\n", ntohl(worker1_reply[22]) + ntohl(worker2_reply[22]) );
    printf("x %d\n", ntohl(worker1_reply[23]) + ntohl(worker2_reply[23]) );
    printf("y %d\n", ntohl(worker1_reply[24]) + ntohl(worker2_reply[24]) );
    printf("z %d\n", ntohl(worker1_reply[25]) + ntohl(worker2_reply[25]) );

     
    close(sock1);
    close(sock2);
    return 0;
}
