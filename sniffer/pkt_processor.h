#ifndef PKT_PROCESSOR_H
#define PKT_PROCESSOR_H

#include <QThread>
#include <QMutex>
#include <tins/tins.h>
#include "sniffer/pkt_worker.h"
#include "sniffer/pkt_info.h"

class pkt_processor : public pkt_worker
{
        Q_OBJECT
    public:
        explicit pkt_processor(queue_t *pkt_queue, QMutex *stop_mutex);
    private:
        void run();
    signals:
        void new_pkt(struct pkt_info_t *pkt_info);
    private:
        void proc_pkt(Tins::Packet *pkt);
        const char *__timestamp_to_str(Tins::Timestamp &timestamp);
    private:
        unsigned long pkt_cnt;

};

#endif // PKT_PROCESSOR_H
