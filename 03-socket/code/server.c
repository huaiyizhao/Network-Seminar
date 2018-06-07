/* server application */
 
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
 
int main(int argc, const char *argv[])
{
    int s, cs;
    struct sockaddr_in server, client;
     
    // Create socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Could not create socket");
		return -1;
    }
    printf("Socket created");
     
    // Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(12345);
     
    // Bind
    if (bind(s,(struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("bind failed. Error");
        return -1;
    }
    printf("bind done");
     
    // Listen
    listen(s, 1);
     
    // Accept and incoming connection
    printf("Waiting for incoming connections...");
     
    // accept connection from an incoming client
    int c = sizeof(struct sockaddr_in);
    if ((cs = accept(s, (struct sockaddr *)&client, (socklen_t *)&c)) < 0) {
        perror("accept failed");
        return 1;
    }
    printf("Connection accepted");
    
    //receive
	uint32_t net_msg_len;
    if (recv(cs, &net_msg_len, 4, 0) < 0) {
        printf("Error Receive message length\n");
        return 1;
    }
    uint32_t msg_len = ntohl(net_msg_len);
    // printf("message length = %d", msg_len);
    char pwd[100];
    if (recv(cs, pwd, msg_len - 12, 0) < 0) {
        printf("Error Receive pwd\n");
    }
    // printf("pwd = %s\n", pwd);     
    uint32_t net_begin, net_end;
    if (recv(cs, &net_begin, 4, 0) < 0 || recv(cs, &net_end, 4, 0) < 0) {
        printf("Error Receive boundary\n");
    }
    uint32_t begin = ntohl(net_begin);
    uint32_t end = ntohl(net_end);
   
    //exec
    long begin_long = begin;
    int position; 
    char buf;   
    uint32_t result[26] = {0};
    FILE * fp = fopen(pwd, "rb");
    fseek(fp, begin_long, SEEK_SET);
    for (position = 0; position < end - begin; position++){
        fread(&buf, 1, 1, fp);
        if (buf >= 65 && buf <= 90) buf += 32;
        if (buf >= 97 && buf <= 122) result[buf - 97] += 1;
    }
    fclose(fp);
    //send
    uint32_t net_result[26];
    int i;
    for (i = 0; i < 26; i ++)
        net_result[i] = htonl(result[i]);
    if (send(cs, net_result, 104, 0) < 0){
        printf("Error send to master\n");
        return 1;
    }
    return 0;
}
