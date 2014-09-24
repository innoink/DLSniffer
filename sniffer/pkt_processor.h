#ifndef PKT_PROCESSOR_H
#define PKT_PROCESSOR_H

#include <QThread>
#include <QMutex>
#include <tins/tins.h>
#include "utils/queue.h"

struct pkt_info_t {
        unsigned long pkt_num;
        char timestr[64];
        char srcip[16], dstip[16];

};

class pkt_processor : public QThread
{
        Q_OBJECT
    public:
        explicit pkt_processor(queue_t *pkt_queue, QMutex *stop_mutex);
        void start_thrd();
        void stop_thrd();
    protected:
        void run();

    signals:
        void new_pkt(struct pkt_info_t *pkt_info);

    private:
        void proc_pkt(Tins::Packet *pkt);
    private:
        queue_t *pkt_queue;
        QMutex *stop_mutex;
        bool stop;
        unsigned long pkt_cnt;

};

#endif // PKT_PROCESSOR_H
