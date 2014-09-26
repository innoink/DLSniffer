#include "pkt_worker.h"

pkt_worker::pkt_worker(queue_t *pkt_queue, QReadWriteLock *stop_rwlock) :
    pkt_queue(pkt_queue), stop_rwlock(stop_rwlock), stop(true)
{
}

pkt_worker::~pkt_worker()
{
}

void pkt_worker::start_work()
{
    if (!stop) return;
    stop_rwlock->lockForWrite();
    stop = false;
    stop_rwlock->unlock();
    start();
}

void pkt_worker::stop_work()
{
    if (stop) return;
    stop_rwlock->lockForWrite();
    stop = true;
    stop_rwlock->unlock();
}
