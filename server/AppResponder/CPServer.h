#ifndef CPSERVER_H
#define CPSERVER_H

#include "CPTask.h"
#include <glog/logging.h>
#include <netinet/in.h>
#include <atomic>

class CPTask; 

class CPServer {
private:
    int m_server_sock_fd;
    int epfd;
    std::atomic<bool> m_shutdown;
    CPTask* m_cptask;

public:
    CPServer() : m_server_sock_fd(-1), epfd(-1), m_shutdown(false), m_cptask(nullptr) {}
    ~CPServer() { shutDown(); }
    
    int init();
    void doWork();
    void shutDown();
    void setCPTask(CPTask* task) { m_cptask = task; }
};

#endif
