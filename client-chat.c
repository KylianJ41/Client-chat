#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <poll.h>
#include <netdb.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#define CHECK(op)   do { if ( (op) == -1) { perror (#op); exit (EXIT_FAILURE); } \
                    } while (0)

#define PORT(p) htons(p)
#define MAXCMD 7
#define BUFFSIZE 255
#define FILENAME_MAX_LENGTH 100


typedef enum {
    CMD_HELO = 0b0001,
    CMD_QUIT = 0b0010,
    CMD_FILE_START = 0b0100,
    CMD_FILE_END = 0b0101
} command;

int sendCommand(int sockfd, const struct sockaddr *dest_addr, socklen_t addrlen, command cmd) {
    ssize_t sent_bytes = sendto(sockfd, &cmd, sizeof(cmd), 0, dest_addr, addrlen);
    if (sent_bytes == -1) {
        perror("sendto failed");
        return -1;
    }
    return 0;
}

void extractFilename(const char *input, char *filename) {
    // Assuming input format is "/FILE filename.txt"
    const char *filenameStart = strchr(input, ' ');
    if (filenameStart != NULL) {
        snprintf(filename, FILENAME_MAX_LENGTH, "%s", filenameStart + 1);

        // Remove trailing newline or carriage return
        filename[strcspn(filename, "\r\n")] = '\0';
    } else {
        filename[0] = '\0'; // No filename found
    }
}

int sendFileStart(int sockfd, const struct sockaddr *dest_addr, socklen_t addrlen, const char *filename) {
    char buffer[BUFFSIZE] = {0};
    command cmd = CMD_FILE_START;
    size_t cmdSize = sizeof(cmd);

    // Manually copy the command into the buffer
    for (size_t i = 0; i < cmdSize; ++i) {
        buffer[i] = ((char*)&cmd)[i];
    }

    // Append the filename to the buffer after the command
    size_t filenameLength = strlen(filename);
    if (filenameLength > BUFFSIZE - cmdSize - 1) {
        filenameLength = BUFFSIZE - cmdSize - 1; // Adjust length to fit, leave 1 byte for null terminator
    }

    for (size_t i = 0; i < filenameLength; ++i) {
        buffer[cmdSize + i] = filename[i];
    }

    // Calculate the total size of the buffer to send (command + filename)
    // The total size should include the command size and the filename length
    size_t totalSize = cmdSize + filenameLength;

    // Send the buffer
    ssize_t sent_bytes = sendto(sockfd, buffer, totalSize, 0, dest_addr, addrlen);
    if (sent_bytes == -1) {
        perror("sendto failed in sendFileStart");
        return -1;
    }
    return 0;  // Return 0 on successful completion
}

int sendFileData(int sockfd, const struct sockaddr *dest_addr, socklen_t addrlen, FILE *file) {
    char buffer[BUFFSIZE];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, BUFFSIZE, file)) > 0) {
        ssize_t sent_bytes = sendto(sockfd, buffer, bytesRead, 0, dest_addr, addrlen);
        if (sent_bytes == -1) {
            perror("sendto failed in sendFileData");
            return -1;
        }
    }
    return 0;  // Return 0 on successful completion
}

void handleSendFile(int sockfd, const struct sockaddr *dest_addr, socklen_t addrlen, const char *command, FILE **file) {
    if (*file != NULL) {
        fclose(*file);
        *file = NULL;
    }

    char filename[FILENAME_MAX_LENGTH];
    extractFilename(command, filename);

    *file = fopen(filename, "rb");
    if (*file == NULL) {
        perror("Failed to open file");
        return;
    }

    CHECK(sendFileStart(sockfd, dest_addr, addrlen, filename));
    CHECK(sendFileData(sockfd, dest_addr, addrlen, *file));
    CHECK(sendCommand(sockfd, dest_addr, addrlen, CMD_FILE_END));

    fclose(*file);
    *file = NULL;
}

void handleFileStart(char *buff, ssize_t size_read, FILE **file) {
    if (*file != NULL) {
        fclose(*file);
        *file = NULL;
    }

    char filename[FILENAME_MAX_LENGTH] = {0};
    if (size_read > (long int) sizeof(command)) {
        ssize_t filename_length = size_read - sizeof(command);
        snprintf(filename, FILENAME_MAX_LENGTH, "cpy_%.*s", (int)filename_length, buff + sizeof(command));
    }
    else {
        perror("size_read is too small");
        return;
    }

    *file = fopen(filename, "wb");
    if (*file == NULL) {
        perror("Failed to open file for writing");
    }
}

void handleFileEnd(FILE **file) {
    if (*file) {
        fclose(*file);
        *file = NULL;
    }
    printf("File fully received\n");
}

void clearBuffer(char *buffer, int size) {
    for (int i = 0; i < size; i++)
        buffer[i] = '\0';
}

int handleHeloCommand(const struct sockaddr_storage *ss, socklen_t sslen, char *hbuf, char *sbuf, int *paired) {
    int rslt = getnameinfo((const struct sockaddr*)ss, sslen, hbuf, BUFFSIZE, sbuf, BUFFSIZE, NI_NUMERICHOST | NI_NUMERICSERV);
    if (rslt != 0) {
        fprintf(stderr, "getnameinfo: %s\n", gai_strerror(rslt));
        return -1;
    }
    *paired = 1;
    printf("%s %s\n", hbuf, sbuf);
    return 0;
}

int main (int argc, char *argv [])
{
    /* test arg number */
    if(argc != 2){
        fprintf(stderr, "usage : %s port_number\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* convert and check port number */
    int port = atoi(argv[1]);
    if(port < 10000 || port > 65000){
        fprintf(stderr, "port pas dans l'intervalle");
        exit(EXIT_FAILURE);
    }

    /* create socket */
    int sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    CHECK(sockfd);

    /* set dual stack socket */
    int value = 0; // by setting to 0, we tell setsockopt to accept both v6 and v4
    CHECK(setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof value));

    /* set local addr */
    struct sockaddr_storage ss = {0};
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;
    in6->sin6_family = AF_INET6;
    in6->sin6_port = PORT(port);
    in6->sin6_addr = in6addr_any;

    /* check if a client is already present */
    int isserver = 1;
    if (bind(sockfd, (struct sockaddr*) &ss, sizeof(ss)) == -1) {
        isserver = 0;
    }
    CHECK(sockfd);

    /* prepare struct pollfd with stdin and socket for incoming data */
    struct pollfd pstdin = {STDIN_FILENO, POLLIN, 0};
    struct pollfd psock = {sockfd, POLLIN, 0};
    struct pollfd fds[] = {pstdin, psock};
    FILE *file = NULL;

    /* main loop */
    char buff[BUFFSIZE+MAXCMD] = {0};
    char buffin[BUFFSIZE] = {0};
    char *hbuf = calloc(BUFFSIZE, sizeof(char));
    char *sbuf = calloc(BUFFSIZE, sizeof(char));
    ssize_t size_read = 0;
    socklen_t sslen = sizeof(ss);
    int paired = 0;
    if(!isserver){
        CHECK(sendCommand(sockfd, (struct sockaddr*)&ss, sizeof(ss), CMD_HELO));
        printf("You're not master, you sent /HELO to master.\n");
        paired = 1;
    }
    
    while (1) {
        CHECK(poll(fds, 2, -1));
        
        //receive chat
        if (fds[1].revents & POLLIN) {
            CHECK(size_read = recvfrom(psock.fd, buff, BUFFSIZE + MAXCMD - 1, 0, (struct sockaddr*)&ss, &sslen));
            buff[size_read] = '\0';
            command *received_cmd = (command *)buff;

            if (*received_cmd == CMD_FILE_START) {
                handleFileStart(buff, size_read, &file);
            } 
            else if (*received_cmd == CMD_FILE_END) {
                handleFileEnd(&file);
            } 
            else if (!paired && *received_cmd == CMD_HELO) {
                CHECK(handleHeloCommand(&ss, sslen, hbuf, sbuf, &paired));
            } 
            else if (*received_cmd == CMD_QUIT) {
                printf("OTHER HAS QUIT... LEAVING CHAT\n");
                break;
            } 
            else if (file != NULL) { // If a file is open, write to it
                fwrite(buff, 1, size_read, file);
                continue;
            } 
            else {
                write(pstdin.fd, buff, size_read + 1);
            }
        }

        //send chat
        if (fds[0].revents & POLLIN) {
            CHECK(size_read = read(pstdin.fd, buffin, BUFFSIZE-1));
            buffin[size_read]='\0';
            if (strncmp(buffin, "/FILE", 5) == 0) {
                handleSendFile(sockfd, (struct sockaddr*)&ss, sizeof(ss), buffin, &file);
                printf("File sent\n");
            }
            else if(strncmp(buffin, "/QUIT", 5) == 0){
                printf("LEAVING CHAT\n");
                CHECK(sendCommand(sockfd, (struct sockaddr*)&ss, sizeof(ss), CMD_QUIT));
                break;
            }
            else
                CHECK(sendto(psock.fd, buffin, size_read, 0, (struct sockaddr*) &ss, sizeof(ss)));
        }

        clearBuffer(buffin, BUFFSIZE);
        clearBuffer(buff, BUFFSIZE + MAXCMD);
    }
    /* close socket */
    CHECK(close(sockfd));
    free(hbuf);
    free(sbuf);
    return 0;
}