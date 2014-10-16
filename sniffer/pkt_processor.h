#ifndef PKT_PROCESSOR_H
#define PKT_PROCESSOR_H

#include <QThread>
#include <QReadWriteLock>
#include <tins/tins.h>
#include <QMultiHash>
#include "sniffer/pkt_worker.h"
#include "sniffer/pkt_info.h"

typedef void (*pdu_processor_t)(const Tins::PDU*, void*);

class pkt_processor : public pkt_worker
{
        Q_OBJECT
    public:
        explicit pkt_processor(queue_t *pkt_queue, QReadWriteLock *stop_rwlock);
        void add_pdu_processor(enum pkt_info_t::pdu_type_t ptype, pdu_processor_t processor);
    private:
        void run();
    signals:
        void new_pkt_info(pkt_info_t *pkt_info);
    private:
        void        proc_pkt(Tins::Packet *pkt);
        const char *__timestamp_to_str(Tins::Timestamp &timestamp);
        bool        __set_app_layer_protocol(struct pkt_info_t *pi);
        void        __run_processors(QPair<enum pkt_info_t::pdu_type_t, Tins::PDU *> &pair);
    private:
        unsigned long pkt_cnt;
        QMultiHash<enum pkt_info_t::pdu_type_t, pdu_processor_t> pdu_processors;

};

#endif // PKT_PROCESSOR_H
