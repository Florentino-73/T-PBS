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
#include "Thread.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <new>
#include <sched.h>
#include <sys/sysinfo.h>
#include <string.h>
#include <errno.h>

#include <sched.h>
/*--------------------------------------------------------------------------------------------------*/

Thread::Thread()
        : m_shutDown(false), m_thread(0) 
{
}

Thread::~Thread()
{
}

void Thread::start()
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    int num_cpus = get_nprocs();
    int target_cpu = 38;  
    
    const char* env_cpu = getenv("THREAD_CPU_CORE");
    if (env_cpu != NULL) {
        int env_target = atoi(env_cpu);
        if (env_target >= 0) {
            target_cpu = env_target;
        }
    }
    
    if (target_cpu >= num_cpus) {
        printf("Warning: CPU core %d does not exist (system has %d cores). Using core %d instead.\n", 
               target_cpu, num_cpus, num_cpus - 1);
        target_cpu = num_cpus - 1;  
    }
    
    CPU_SET(target_cpu, &cpuset);

    int rc = pthread_create(&m_thread, NULL, Thread::doWork, (void*)this);
    if (pthread_setaffinity_np(m_thread, sizeof(cpu_set_t), &cpuset) < 0) {
        printf("Failed to set CPU affinity to core %d: %s\n", target_cpu, strerror(errno));
    }

    assert(rc == 0);
    (void)rc;
}

void Thread::stop()
{
    m_shutDown = true;
}

bool Thread::isStopped()
{
    return m_shutDown;
}

void* Thread::doWork(void* param)
{
    try
    {
        Thread* thread = static_cast<Thread*>(param);
        thread->run();
    }
    catch(std::bad_alloc& allocationException)
    {
        printf("Unable to allocate memory\n");
		(void)allocationException;
        throw;
    }

    return NULL;
};


void Thread::join()
{
    void* res;
    pthread_join(m_thread, &res);
}

/*--------------------------------------------------------------------------------------------------*/
