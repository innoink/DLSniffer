#include "pkt_capture.h"

pkt_capture::pkt_capture(queue_t *pkt_queue, QReadWriteLock *stop_rwlock) :
    pkt_worker(pkt_queue, stop_rwlock)
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
        stop_rwlock->lockForRead();
        if (stop) {
            stop_rwlock->unlock();
            break;
        }
        stop_rwlock->unlock();
        pkt = new Tins::Packet(sniffer->next_packet());
        queue_put_wait(pkt_queue, pkt);
    }
}

