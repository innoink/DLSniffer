#include "pkt_capture.h"

pkt_capture::pkt_capture(queue_t *pkt_queue, QMutex *stop_mutex) :
    pkt_worker(pkt_queue, stop_mutex)
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

