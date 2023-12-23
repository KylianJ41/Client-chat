#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <poll.h>
#include <netdb.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define CHECK(op)   do { if ( (op) == -1) { perror (#op); exit (EXIT_FAILURE); } \
                    } while (0)

#define PORT(p) htons(p)
#define MAXCMD 7
#define BUFFSIZE 255

void clearBuffer(char *buffer, int size) {
    for (int i = 0; i < size; i++) {
        buffer[i] = '\0';
    }
}

int main (int argc, char *argv [])
{
    /* test arg number */
    if(argc != 2){
        fprintf(stderr, "usage : %s port_number\n",argv[0]);
        exit(EXIT_FAILURE);
    }

    /* convert and check port number */
    int port = atoi(argv[1]);
    if(port < 10000 || port > 65000){
        fprintf(stderr,"port pas dans l'intervalle");
        exit(EXIT_FAILURE);
    }

    /* create socket */
    int sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    CHECK(sockfd);

    /* set dual stack socket */
    int value = 0;
    CHECK(setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof value));

    /* set local addr */
    struct sockaddr_in6 ss;
    clearBuffer((char *)&ss, sizeof(ss));
    struct sockaddr *s = (struct sockaddr *)&ss;
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;
    in6->sin6_family = AF_INET6;
    in6->sin6_port = PORT(port);
    in6->sin6_addr = in6addr_any;

    /* check if a client is already present */
    short ismaster = 1;
    if (bind(sockfd, s, sizeof(ss)) == -1) {
        CHECK(connect(sockfd,s,sizeof(ss)));
        ismaster= 0;
    }
    CHECK(sockfd);

    /* prepare struct pollfd with stdin and socket for incoming data */

    struct pollfd pstdin = {STDIN_FILENO,POLLIN,0};
    struct pollfd psock = {sockfd, POLLIN,0};
    struct pollfd fds[] = {pstdin,psock};

    /* main loop */

    char buff[BUFFSIZE+MAXCMD];
    char buffin[BUFFSIZE];
    clearBuffer(buffin, BUFFSIZE);
    clearBuffer(buff, BUFFSIZE+MAXCMD);
    ssize_t size_read = 0;
    socklen_t sslen = sizeof(ss);
    short paired = 0;
    if(!ismaster){
        CHECK(sendto(psock.fd,"/HELO",5,0,s,sizeof(ss)));
        printf("You're not master, you sent /HELO to master.\n");
        paired = 1;
    }
    
    while (1) {
        poll(fds, 2, -1);
        if(!paired){
            if(fds[1].revents & POLLIN){
                size_read = recvfrom(psock.fd,buffin,BUFFSIZE-1,0,s,&sslen);
                char * hbuf = malloc(sizeof(char)*BUFFSIZE);
                char * sbuf = malloc(sizeof(char)*BUFFSIZE);
                clearBuffer(hbuf, BUFFSIZE);
                clearBuffer(sbuf, BUFFSIZE);
                if(strncmp(buffin,"/HELO",5) == 0){
                    CHECK(getnameinfo((struct sockaddr*)&ss,sslen, hbuf, BUFFSIZE,sbuf,BUFFSIZE,NI_NUMERICHOST | NI_NUMERICSERV ));
                    paired = 1;
                    printf("%s %s\n",hbuf,sbuf);
                }
                free(hbuf);
                free(sbuf);
            }
            continue;
        }
        //send chat
        if (fds[0].revents & POLLIN) {
            size_read = read(pstdin.fd,buffin,BUFFSIZE-1);
            buffin[BUFFSIZE-1]='\0';
            size_read = snprintf(buff,BUFFSIZE+MAXCMD-1,"%s",buffin);
            if(strncmp(buffin,"/QUIT",5) == 0){
                char * out = "LEAVING CHAT\n";
                write(pstdin.fd,out,strlen(out));
                CHECK(sendto(psock.fd,"/QUIT",5,0,s,sizeof(ss)));
                break;
            }
            buff[size_read] = '\0';
            CHECK(sendto(psock.fd,buff,size_read,0,s,sizeof(ss)));
            
        }

        //receive chat
        if (fds[1].revents & POLLIN) {
            /* Receive and print incoming messages */
            size_read = recvfrom(psock.fd, buff, BUFFSIZE+MAXCMD-1,0,s,&sslen);
            CHECK(size_read);
            buff[size_read] = '\0';
            if(strncmp(buff,"/QUIT",5) == 0){
                char * out = "OTHER HAS QUIT... LEAVING CHAT\n";
                write(pstdin.fd,out,strlen(out));
                break;
            }
            if(strncmp(buff,"/HELO",5) != 0)
                write(pstdin.fd,buff,size_read+1);
        }

        clearBuffer(buffin, BUFFSIZE);
        clearBuffer(buff, BUFFSIZE + MAXCMD);
    }
    
    /* close socket */
    close(sockfd);
    return 0;
}
