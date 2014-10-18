#include "pkt_capture.h"

pkt_capture::pkt_capture(queue_t *pkt_queue) :
    pkt_worker(pkt_queue)
{
}

void pkt_capture::set_sniffer(Tins::Sniffer *sniffer)
{
    this->sniffer = sniffer;
}

void pkt_capture::run()
{
    Tins::Packet *pkt;
    sniffer->set_extract_raw_pdus(true);
    while (true) {
        if (stop.load()) {
            break;
        }
        pkt = new Tins::Packet(sniffer->next_packet());
        queue_put_wait(pkt_queue, pkt);
    }
}

