#ifndef PKT_CAPTURE_H
#define PKT_CAPTURE_H

#include <QThread>
#include <QMutex>
#include <tins/tins.h>
#include "utils/queue.h"

class pkt_capture : public QThread
{
        Q_OBJECT
    public:
        explicit pkt_capture(queue_t *q, QMutex *stop_mutex);
        void set_sniffer(Tins::Sniffer *sniffer);
        void start_thrd();
        void stop_thrd();
    private:
        void run();
    private:
        Tins::Sniffer *sniffer;
        queue_t *pkt_queue;
        QMutex *stop_mutex;
        bool stop;

};

#endif // PKT_CAPTURE_H
