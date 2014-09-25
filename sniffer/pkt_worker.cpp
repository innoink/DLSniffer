#include "pkt_worker.h"

pkt_worker::pkt_worker(queue_t *pkt_queue, QMutex *stop_mutex) :
    pkt_queue(pkt_queue), stop_mutex(stop_mutex), stop(true)
{
}

pkt_worker::~pkt_worker()
{
}

void pkt_worker::start_work()
{
    if (!stop) return;
    stop_mutex->lock();
    stop = false;
    stop_mutex->unlock();
    start();
}

void pkt_worker::stop_work()
{
    if (stop) return;
    stop_mutex->lock();
    stop = true;
    stop_mutex->unlock();
}
