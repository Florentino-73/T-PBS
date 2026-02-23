#ifndef _CPTASK_H_
#define _CPTASK_H_

#include "Thread.h"
#include "Queue.h"
#include "Scheduler.h"
#include <ctime>

#include "benchmark.h"
#include "fifo_def.h"
#include "../Include/datatypes.h"

class CPTask : public Thread 
{
public:
	CPTask(int _pageSize, int _numThreads, int _managerCap);
	~CPTask(){}

	virtual void puttask(FIFO_MSG * request);
	virtual void shutdown();

private:
	int pageSize;
	int numThreads;
	int managerCap;
	virtual void run();

	CPTask& operator=(const CPTask&);
	CPTask(const CPTask&);
	// Queue<FIFO_MSG>  m_queue;
    Scheduler m_scheduler;
};

#endif

