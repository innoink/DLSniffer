#ifndef PKT_CAPTURE_H
#define PKT_CAPTURE_H

#include <QThread>
#include <QMutex>
#include <tins/tins.h>
#include "sniffer/pkt_worker.h"

class pkt_capture : public pkt_worker
{
        Q_OBJECT
    public:
        explicit pkt_capture(queue_t *pkt_queue, QMutex *stop_mutex);
        void set_sniffer(Tins::Sniffer *sniffer);
    private:
        void run();
    private:
        Tins::Sniffer *sniffer;

};

#endif // PKT_CAPTURE_H
