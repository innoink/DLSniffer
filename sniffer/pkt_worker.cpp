#include "pkt_worker.h"

pkt_worker::pkt_worker(queue_t *pkt_queue) :
    pkt_queue(pkt_queue)
{
    stop.store(true);
}

pkt_worker::~pkt_worker()
{
    stop_work();
}

void pkt_worker::start_work()
{
    if (!stop.load()) return;
    stop.store(false);
    start();
}

void pkt_worker::stop_work()
{
    if (stop.load()) return;
    stop.store(true);
}
