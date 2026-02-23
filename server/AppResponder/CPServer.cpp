#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "CPServer.h"
#include "fifo_def.h"
#include "config.h"

#include <glog/logging.h>

#define BACKLOG 5 
#define CONCURRENT_MAX 1024
#define BUFFER_SIZE 1024
#define MAX_MSG_SIZE (16 * 1024 * 1024)  /* 16 MB upper limit for message size */

int CPServer::init()
{

    LOG(INFO) << "CPServer init.";

    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));

    m_server_sock_fd = socket(AF_INET, SOCK_STREAM, 0); 
    if (m_server_sock_fd == -1)
    {
        LOG(ERROR)<<"socket initialization error.";
        return -1;
    }

    int opt = 1;
    setsockopt(m_server_sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = INADDR_ANY;
    serveraddr.sin_port = htons(get_server_port());
    int bind_result = bind(m_server_sock_fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if (bind_result == -1)
    {
        LOG(ERROR)<<"bind error.";
        close(m_server_sock_fd);
        return -1;
    }

    if (listen(m_server_sock_fd, BACKLOG) == -1)
    {
        LOG(ERROR)<<"listen error.";
        close(m_server_sock_fd);
        return -1;
    }

    epfd = epoll_create(1);
    struct epoll_event ev;
    ev.data.fd = m_server_sock_fd;
    // ev.events = EPOLLIN | EPOLLET; // read && edge trigger
    ev.events = EPOLLIN; // level trigger

    epoll_ctl(epfd, EPOLL_CTL_ADD, m_server_sock_fd, &ev);

    LOG(INFO) << "Server listening on " << get_server_addr() << ":" << get_server_port();

    return 0;
}

/* Function Description:
 * This function is server's major routine, it uses select() to accept new connection and receive messages from clients.
 * When it receives clients' request messages, it would put the message to task queue and wake up worker thread to process the requests.
 * */
void CPServer::doWork()
{
    int nfds, connfd;
    char recv_msg[BUFFER_SIZE + 1];
    struct epoll_event events[CONCURRENT_MAX], ev;
    struct sockaddr_in clt_addr;

    FIFO_MSG *msg;

    while (!m_shutdown)
    {
        nfds = epoll_wait(epfd, events, CONCURRENT_MAX, 500);
        if (nfds == -1)
        {
            continue;
        }

        for (int i = 0; i < nfds; ++i)
        {
            int clientfd = events[i].data.fd;

            if (clientfd == m_server_sock_fd)
            {
                struct sockaddr_in client;
                socklen_t rcvLen = sizeof(client);
                connfd = accept(m_server_sock_fd, (struct sockaddr *)&client, &rcvLen);
                if (connfd < 0)
                {
                    printf("connfd < 0: %s(errno: %d)\n", strerror(errno), errno);
                    exit(1);
                }

                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client.sin_addr, client_ip, INET_ADDRSTRLEN);
                LOG(INFO)<<"New connection from " << client_ip << ":" << ntohs(client.sin_port) << ", connfd: " << connfd;

                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = connfd;
                epoll_ctl(epfd, EPOLL_CTL_ADD, connfd, &ev);
            }
            else if (events[i].events & EPOLLIN)
            { 
                // if read
                LOG(INFO)<<"Receiving Epoll Connection, current client fd is "<<clientfd;

                FIFO_MSG_HEADER header;
                long total_read = 0;
                bool read_error = false;

                while (total_read < (long)sizeof(FIFO_MSG_HEADER)) {
                    long ret = recv(clientfd, (char*)&header + total_read, sizeof(FIFO_MSG_HEADER) - (size_t)total_read, 0);
                    if (ret <= 0) {
                        LOG(ERROR)<<"Failed to read header or connection closed. ret: " << ret;
                        read_error = true;
                        break;
                    }
                    total_read += ret;
                }

                if (read_error) {
                    close(clientfd);
                    epoll_ctl(epfd, EPOLL_CTL_DEL, clientfd, &ev);
                    continue;
                }

                if (header.size > MAX_MSG_SIZE) {
                    LOG(ERROR)<<"Message size " << header.size << " exceeds maximum allowed " << MAX_MSG_SIZE;
                    close(clientfd);
                    epoll_ctl(epfd, EPOLL_CTL_DEL, clientfd, &ev);
                    continue;
                }

                size_t alloc_size = sizeof(FIFO_MSG_HEADER) + header.size;
                if (alloc_size < sizeof(FIFO_MSG)) alloc_size = sizeof(FIFO_MSG);
                
                msg = (FIFO_MSG *)malloc(alloc_size);
                if (!msg)
                {
                    LOG(ERROR)<<"epoll return msg memory allocation failure";
                    exit(-1);
                }
                memset(msg, 0, alloc_size);
                memcpy(&msg->header, &header, sizeof(FIFO_MSG_HEADER));
                msg->header.sockfd = clientfd;

                if (header.size > 0) {
                    total_read = 0;
                    while (total_read < header.size) {
                        // Read directly into msgbuf (offset by header size)
                        long ret = recv(clientfd, (char*)msg + sizeof(FIFO_MSG_HEADER) + total_read, header.size - total_read, 0);
                        if (ret <= 0) {
                            LOG(ERROR)<<"Failed to read body. ret: " << ret;
                            read_error = true;
                            break;
                        }
                        total_read += ret;
                    }
                }

                if (read_error) {
                    free(msg);
                    close(clientfd);
                    epoll_ctl(epfd, EPOLL_CTL_DEL, clientfd, &ev);
                    continue;
                }

                LOG(INFO)<<"msg header type is "<< msg->header.type;

                if (msg->header.type == FIFO_USER_FILE)
                {
                        LOG(INFO)<<"receive fifo user file package.";
                        USER_FILE_HEADER *file_header = (USER_FILE_HEADER *)msg->msgbuf;
                        char *filename;
                        get_encrypted_filename(file_header->data_id, &filename);

                        LOG(INFO)<<"RECEIVING user file, saving in "<<filename;

                        FIFO_MSG *fifo_resp = NULL;
                        fifo_resp = (FIFO_MSG *)malloc(sizeof(FIFO_MSG));
                        fifo_resp->header.size = 0;
                        fifo_resp->header.type = FIFO_USER_FILE_RCV;
                        
                        
                        if (send(clientfd, reinterpret_cast<char *>(fifo_resp), static_cast<int>(sizeof(FIFO_MSG)), 0) == -1)
                        {
                            LOG(ERROR)<<"fail to send response fd " << clientfd <<", errono is "<<strerror(errno);
                            // retcode = -1;
                        }

                        LOG(INFO)<<"SEND BACK FIFO_USER_FILE_RCV, start receiving enbcrypted file";

                        // free(fifo_resp);

                        FILE *file = fopen(filename, "w+b");
                        if (!file)
                        {
                            LOG(ERROR)<<"cannot open file " << filename<<", error no: "<<errno <<strerror(errno);
                            // continue; // Should probably close connection or handle error better
                        }
                        else 
                        {
                            uint32_t total_size = file_header->file_size;
                            int count = 0;
                            while (total_size > 0)
                            {
                                LOG(INFO)<<"RECEIVE file size remains "<< total_size;
                                // Use recv_msg buffer for file data
                                count = recv(clientfd, recv_msg, BUFFER_SIZE, 0);
                                if (count <= 0) {
                                    LOG(ERROR)<<"Error receiving file data";
                                    break;
                                }
                                fwrite(recv_msg, count, 1, file);
                                total_size -= count;
                            }
                            fclose(file);
                        }
                        free(filename);
                        free(fifo_resp); 
                        LOG(INFO)<<"fifo user file package process end..";
                        free(msg);
                        continue;
                }

                m_cptask->puttask(msg);
                LOG(INFO)<<"put task";
            }
        }
    }
}

/* Function Description:
 * This function is to shutdown server. It's called when process exits.
 * */
void CPServer::shutDown()
{
    printf("Server would shutdown...\n");
    m_shutdown = 1;
    m_cptask->shutdown();
    close(m_server_sock_fd);
}
