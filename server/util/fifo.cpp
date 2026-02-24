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

#define BUFFER_SIZE 1024

const uint32_t filename_size = 42;
uint32_t get_encrypted_filename(uint32_t data_id, char **new_filename){
    char *filename = (char *)malloc(filename_size);
    memset(filename, 0, filename_size);
    snprintf(filename, filename_size, "../test_data/gwas_encrypted/%08x.gwas", data_id);
    *new_filename = filename;

    return 0; // SUCCESS
}

int message_return(FIFO_MSG *msg, int client_sockfd)
{
    int retcode = 0;
    LOG(INFO)<<"message return to client fd: "<<client_sockfd;

    if (send(client_sockfd, reinterpret_cast<char *>(msg), static_cast<int>(sizeof(FIFO_MSG) + msg->header.size), 0) == -1)
    {
        LOG(ERROR)<<"fail to send response fd " << client_sockfd <<", errno is "<<strerror(errno);
        retcode = -1;
    }

    return retcode;
}

int send_file(int client_sockfd, const char* filename, uint32_t file_size)
{
    LOG(INFO) << "Server sending file to client fd: " << client_sockfd;
    
    int ret = 0;
    char buffer[BUFFER_SIZE] = {0};
    FILE *file;
    long byte_num;
    int total = file_size;
    int count = 0;

    // First, send the ready signal
    FIFO_MSG ready_msg;
    memset(&ready_msg, 0, sizeof(FIFO_MSG));
    ready_msg.header.type = FIFO_USER_FILE_RCV;
    ready_msg.header.size = 0;

    if (send(client_sockfd, reinterpret_cast<char *>(&ready_msg), sizeof(FIFO_MSG), 0) == -1)
    {
        LOG(ERROR)<<"Failed to send ready signal, errno: " << strerror(errno);
        return -1;
    }

    LOG(INFO)<<"Sent ready signal, opening file: " << filename;

    file = fopen(filename, "rb");
    if (file == NULL)
    {
        LOG(ERROR) << "FAILED TO OPEN FILE: " << filename;
        return -1;
    }

    LOG(INFO)<<"READY TO send file, file size is: " << total;
    
    while (total > 0)
    {
        count = fread(buffer, 1, BUFFER_SIZE, file);
        if (count <= 0)
        {
            LOG(INFO)<<"Reading finished, remaining: " << total;
            break;
        }
        
        byte_num = send(client_sockfd, buffer, count, 0);
        if (byte_num == -1)
        {
            LOG(ERROR)<<"Send error: " << strerror(errno);
            ret = -1;
            break;
        }

        total -= byte_num;
        LOG(INFO)<<"Sent " << byte_num << " bytes, remaining: " << total;
    }

    fclose(file);
    LOG(INFO) << "File transfer complete.";
    
    return ret;
}