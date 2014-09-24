#include "pkt_processor.h"
#include <ctime>
#include <cstdio>

#include <QDebug>

pkt_processor::pkt_processor(queue_t *pkt_queue, QMutex *stop_mutex) :
    pkt_queue(pkt_queue), stop_mutex(stop_mutex), stop(false), pkt_cnt(0)
{
}
void pkt_deleter(void *pkt)
{
    Tins::Packet *pkt_ = (Tins::Packet *)pkt;
    delete pkt_;
}

void pkt_processor::run()
{
    Tins::Packet *pkt;
    pkt_cnt = 0;
    while (true) {
        stop_mutex->lock();
        if (stop) {
            stop_mutex->unlock();
            break;
        }
        stop_mutex->unlock();
        queue_get_wait(pkt_queue, (void **)&pkt);
        proc_pkt(pkt);
        delete pkt;
    }
    queue_flush_complete(pkt_queue, pkt_deleter);

    qDebug() << "PP Stoppped";
}

void pkt_processor::start_thrd()
{
    stop_mutex->lock();
    stop = false;
    stop_mutex->unlock();
    start();
}

void pkt_processor::stop_thrd()
{
    stop_mutex->lock();
    stop = true;
    stop_mutex->unlock();
}

void pkt_processor::proc_pkt(Tins::Packet *pkt)
{
    struct pkt_info_t *pkt_info;
    pkt_info = new struct pkt_info_t;
    Tins::Timestamp tv = pkt->timestamp();
    time_t sec_tv = tv.seconds();
    struct tm *localtm = std::localtime(&sec_tv);
    static char tmp[32];
    std::strftime(tmp, 32, "%F %T", localtm);
    std::snprintf(pkt_info->timestr, 64, "%s %lu",
                  tmp, (unsigned long)tv.microseconds());

    Tins::PDU *pdu;
    pdu = pkt->pdu();
    Tins::IP *ip = pdu->find_pdu<Tins::IP>();
    if (ip != nullptr) {
        pkt_info->pkt_num = ++pkt_cnt;
        std::strncpy(pkt_info->srcip, ip->src_addr().to_string().c_str(), 16);
        std::strncpy(pkt_info->dstip, ip->dst_addr().to_string().c_str(), 16);
        emit new_pkt(pkt_info);
    }
}
