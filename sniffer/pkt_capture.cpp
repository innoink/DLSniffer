#include "pkt_capture.h"

pkt_capture::pkt_capture(queue_t *q, QMutex *stop_mutex) :
    pkt_queue(q), stop_mutex(stop_mutex), stop(false)
{
}

void pkt_capture::set_sniffer(Tins::Sniffer *sniffer)
{
    this->sniffer = sniffer;
}

void pkt_capture::run()
{
    Tins::Packet *pkt;
    while (true) {
        stop_mutex->lock();
        if (stop) {
            stop_mutex->unlock();
            break;
        }
        stop_mutex->unlock();
        pkt = new Tins::Packet(sniffer->next_packet());
        queue_put_wait(pkt_queue, pkt);
    }
}

void pkt_capture::start_thrd()
{
    stop_mutex->lock();
    stop = false;
    stop_mutex->unlock();
    start();
}

void pkt_capture::stop_thrd()
{
    stop_mutex->lock();
    stop = true;
    stop_mutex->unlock();
}
