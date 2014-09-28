#ifndef PKT_PROCESSOR_H
#define PKT_PROCESSOR_H

#include <QThread>
#include <QReadWriteLock>
#include <tins/tins.h>
#include "sniffer/pkt_worker.h"
#include "sniffer/pkt_info.h"

class pkt_processor : public pkt_worker
{
        Q_OBJECT
    public:
        explicit pkt_processor(queue_t *pkt_queue, QReadWriteLock *stop_rwlock);
    private:
        void run();
    signals:
        void new_pkt_info(pkt_info_t *pkt_info);
    private:
        void proc_pkt(Tins::Packet *pkt);
        const char *__timestamp_to_str(Tins::Timestamp &timestamp);
        bool __set_app_layer_protocol(struct pkt_info_t *pi);
    private:
        unsigned long pkt_cnt;

};

#endif // PKT_PROCESSOR_H
