/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <glog/logging.h>

#include "fifo_def.h"
#include "config.h"

#define BUFFER_SIZE 1024

/* Function Description: this is for client to send request message and receive response message
 * Parameter Description:
 * [input] fiforequest: this is pointer to request message
 * [input] fiforequest_size: this is request message size
 * [output] fiforesponse: this is pointer for response message, the buffer is allocated inside this function
 * [output] fiforesponse_size: this is response message size
 * */
int client_send_receive(FIFO_MSG *fiforequest, size_t fiforequest_size, FIFO_MSG **fiforesponse, size_t *fiforesponse_size)
{
    int ret = 0;
    long byte_num;
    char recv_msg[BUFFER_SIZE + 1] = {0};
    FIFO_MSG *response = NULL;
    size_t total_received = 0;
    ssize_t bytes_received = 0;
    FIFO_MSG_HEADER header;

    struct sockaddr_in server_addr;
    int server_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock_fd == -1)
    {
        printf("socket error");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(get_server_port());
    inet_pton(AF_INET, get_server_addr(), &server_addr.sin_addr);

    if (connect(server_sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0)
    {
        printf("01 - connection error, %s, line %d.\n", strerror(errno), __LINE__);
        ret = -1;
        goto CLEAN;
    }

    LOG(INFO)<<"Connected.";

    if ((byte_num = send(server_sock_fd, reinterpret_cast<char *>(fiforequest), static_cast<int>(fiforequest_size), 0)) == -1)
    {
        printf("02 - connection error, %s, line %d..\n", strerror(errno), __LINE__);
        ret = -1;
        goto CLEAN;
    }

    LOG(INFO)<<"SEND, waiting for resp";

    // Receive header
    total_received = 0;
    bytes_received = 0;

    while (total_received < sizeof(FIFO_MSG_HEADER)) {
        bytes_received = recv(server_sock_fd, (char*)&header + total_received, sizeof(FIFO_MSG_HEADER) - total_received, 0);
        if (bytes_received <= 0) {
            printf("server error or closed connection during header recv, error: %s\n", strerror(errno));
            ret = -1;
            goto CLEAN;
        }
        total_received += bytes_received;
    }

    // Allocate memory for the full message
    {
        size_t alloc_size = sizeof(FIFO_MSG_HEADER) + header.size;
        if (alloc_size < sizeof(FIFO_MSG)) alloc_size = sizeof(FIFO_MSG);

        response = (FIFO_MSG *)malloc(alloc_size);
        if (!response) {
            printf("memory allocation failure.\n");
            ret = -1;
            goto CLEAN;
        }
        memset(response, 0, alloc_size);
    }
    
    // Copy header
    memcpy(&response->header, &header, sizeof(FIFO_MSG_HEADER));

    // Receive body
    if (header.size > 0) {
        total_received = 0;
        while (total_received < header.size) {
            bytes_received = recv(server_sock_fd, (char*)response + sizeof(FIFO_MSG_HEADER) + total_received, header.size - total_received, 0);
            if (bytes_received <= 0) {
                printf("server error or closed connection during body recv, error: %s\n", strerror(errno));
                free(response);
                ret = -1;
                goto CLEAN;
            }
            total_received += bytes_received;
        }
    }

    *fiforesponse = response;
    *fiforesponse_size = sizeof(FIFO_MSG_HEADER) + header.size;
    ret = 0;

CLEAN:
    close(server_sock_fd);

    return ret;
}

int client_send_file(FIFO_MSG *file_header, size_t header_size, const char *filename, FIFO_MSG **fiforesponse, size_t *fiforesponse_size)
{
    int ret = 0, count = 0, total = 0;
    long byte_num;
    char recv_msg[BUFFER_SIZE + 1] = {0};
    char buffer[BUFFER_SIZE] = {0};
    FIFO_MSG *response;
    FILE *file;

    USER_FILE_HEADER *header = (USER_FILE_HEADER *)file_header->msgbuf;
    total = header->file_size;

    struct sockaddr_in server_addr;
    int server_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock_fd == -1)
    {
        printf("socket error");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(get_server_port());
    inet_pton(AF_INET, get_server_addr(), &server_addr.sin_addr);

    if (connect(server_sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0)
    {
        printf("01 - connection error, %s, line %d.\n", strerror(errno), __LINE__);
        ret = -1;
        goto CLEAN;
    }

    LOG(INFO)<<"ESTABLISHED Connection, ready to send header req, size is: "<< header_size;
    // sending file header:
    if ((byte_num = send(server_sock_fd, reinterpret_cast<char *>(file_header), static_cast<int>(header_size), 0)) == -1)
    {
        printf("02 - connection error, %s, line %d..\n", strerror(errno), __LINE__);
        ret = -1;
        goto CLEAN;
    }

    LOG(INFO)<<"Sending header, waiting to recv resp. ";
    // rcv ready signal
    byte_num = recv(server_sock_fd, reinterpret_cast<char *>(recv_msg), BUFFER_SIZE, 0);
    if (byte_num > 0)
    {
        if (byte_num > BUFFER_SIZE)
        {
            byte_num = BUFFER_SIZE;
        }
        recv_msg[byte_num] = '\0';
        response = (FIFO_MSG *)malloc((size_t)byte_num);
        if (!response)
        {
            printf("memory allocation failure.\n");
            ret = -1;
            goto CLEAN;
        }
        memset(response, 0, (size_t)byte_num);
        memcpy(response, recv_msg, (size_t)byte_num);
        if (response->header.type != FIFO_USER_FILE_RCV)
        {
            LOG(WARNING)<<"CANNOT RECB ACK, header type is: "<<response->header.type;
            return -1;
        }
    }
    else if (byte_num < 0)
    {
        printf("server error, error message is %s!\n", strerror(errno));
        ret = -1;
        goto CLEAN;
    }
    else
    {
        printf("server exit!\n");
        ret = -1;
        return ret;
    }

    LOG(INFO)<<"RECEIVED RESP of sending file, prepare to send file "<<filename;

    /*SENDING FILE*/
    file = fopen(filename, "rb");
    // file = fopen("../test_data/gwas/client_*.gwas", "rb");
    if (file == NULL)
    {
        LOG(ERROR) << "FAILED TO OPEN FILE: " << filename;
        return -1;
    }

    LOG(INFO)<<"READY TO send encrypted file, file size is: "<<total;
    while (total > 0)
    {
        count = fread(buffer, 1, BUFFER_SIZE, file);
        if (count <= 0)
        {
            printf("reading nothing. return, current total:%d total\n", total);
            break;
        }
        byte_num = send(server_sock_fd, buffer, count, 0);
        if (byte_num == -1)
        {
            printf("02 - connection error, %s, line %d..\n", strerror(errno), __LINE__);
            ret = -1;
            goto CLEAN;
        }

        total -= byte_num;
        // if (byte_num != 1024)
        //     printf("remains size: %d.\n", total);
    }

    // if (shutdown(server_sock_fd, SHUT_WR)!=0){
    //     printf("02- connection error, %s, line %d..\n", strerror(errno), __LINE__);
    // }

    fclose(file);

    LOG(INFO)<<"SEND FILE END, WAITING TO RECV RESP";

    byte_num = recv(server_sock_fd, reinterpret_cast<char *>(recv_msg), BUFFER_SIZE, 0);

    LOG(INFO)<<"FILE RECV RESP.";

    if (byte_num > 0)
    {
        if (byte_num > BUFFER_SIZE)
        {
            byte_num = BUFFER_SIZE;
        }

        recv_msg[byte_num] = '\0';

        response = (FIFO_MSG *)malloc((size_t)byte_num);
        if (!response)
        {
            printf("memory allocation failure.\n");
            ret = -1;
            goto CLEAN;
        }
        memset(response, 0, (size_t)byte_num);

        memcpy(response, recv_msg, (size_t)byte_num);

        *fiforesponse = response;
        *fiforesponse_size = (size_t)byte_num;

        ret = 0;
        // break;
    }
    else if (byte_num < 0)
    {
        printf("server error, error message is %s!\n", strerror(errno));
        ret = -1;
        // goto CLEAN;
    }
    else
    {
        printf("server exit!\n");
        ret = -1;
        return ret;
    }

CLEAN:
    close(server_sock_fd);
    return ret;
}

int user_send_ack()
{
    uint32_t ret = 0, byte_num;
    FIFO_MSG *msg = (FIFO_MSG *)malloc(sizeof(FIFO_MSG));
    if (!msg)
        return -1;

    memset(msg, 0, sizeof(FIFO_MSG));
    msg->header.size = 0;
    msg->header.type = FIFO_SIG_MSG;

    struct sockaddr_in server_addr;
    int server_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock_fd == -1)
    {
        printf("socket error");
        ret = -1;
        goto CLEAN;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(get_server_port());
    inet_pton(AF_INET, get_server_addr(), &server_addr.sin_addr);
    
    if (connect(server_sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0)
    {
        printf("01 - connection error, %s, line %d.\n", strerror(errno), __LINE__);
        ret = -1;
        goto CLEAN;
    }

    // sending file header:
    if ((byte_num = send(server_sock_fd, reinterpret_cast<char *>(msg), static_cast<int>(sizeof(FIFO_MSG)), 0)) == -1)
    {
        printf("02 - connection error, %s, line %d..\n", strerror(errno), __LINE__);
        ret = -1;
        goto CLEAN;
    }

CLEAN:
    close(server_sock_fd);
    return ret;
}