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

int client_send_receive(FIFO_MSG *fiforequest, size_t fiforequest_size, FIFO_MSG **fiforesponse, size_t *fiforesponse_size)
{
    int ret = 0;
    struct sockaddr_in server_addr;
    int server_sock_fd = -1;
    FIFO_MSG_HEADER header;
    FIFO_MSG *response = NULL;
    ssize_t bytes_received;
    size_t total_received;

    LOG(INFO)<<">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>CLIENT SEND.";

    server_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
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

    LOG(INFO)<<"Connected to server " << get_server_addr() << ":" << get_server_port();

    if (send(server_sock_fd, reinterpret_cast<char *>(fiforequest), static_cast<int>(fiforequest_size), 0) == -1)
    {
        printf("connection error, %s, line %d..\n", strerror(errno), __LINE__);
        ret = -1;
        goto CLEAN;
    }

    // Receive header
    total_received = 0;
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
    // Ensure we allocate at least sizeof(FIFO_MSG) to avoid issues with msgbuf access if size is 0
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
            // We assume msgbuf starts right after header. 
            // In the struct definition, msgbuf is at the end. 
            // We use (char*)response + sizeof(FIFO_MSG_HEADER) to be safe and consistent with how we allocated.
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
    if (server_sock_fd != -1) close(server_sock_fd);

    return ret;
}

int client_get_file(FIFO_MSG *file_header, size_t header_size, const char *filename, FIFO_MSG **fiforesponse, size_t *fiforesponse_size)
{
    LOG(INFO)<<">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>Client get file";
    int ret = 0;
    long byte_num;
    char recv_msg[BUFFER_SIZE + 1] = {0};
    char buffer[BUFFER_SIZE] = {0};
    FIFO_MSG *response;
    FILE *file;

    CLIENT_FILE_HEADER *header = (CLIENT_FILE_HEADER *)file_header->msgbuf;

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

    // sending file header:
    if ((byte_num = send(server_sock_fd, reinterpret_cast<char *>(file_header), static_cast<int>(header_size), 0))==-1){
        LOG(ERROR)<<"02 - connection error" <<  strerror(errno) << "line" <<  __LINE__;
        ret = -1;
        goto CLEAN;
    }

    // getting file
    file = fopen(filename, "w+");

    if (!file){
        LOG(ERROR)<< "cannot open file: "<<filename<<", error no: "<<errno <<strerror(errno);
        return -1;
        goto CLEAN;
    }

    while(true){
        int count = recv(server_sock_fd, recv_msg, BUFFER_SIZE, 0);
        if (count<=0){break;}
        
        else{fwrite(recv_msg, count, 1, file); }
    }
    fclose(file);

CLEAN:
    close(server_sock_fd);
    return ret;
}