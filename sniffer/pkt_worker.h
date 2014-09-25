#ifndef PKT_WORKER_H
#define PKT_WORKER_H

#include <QThread>
#include <QMutex>
#include "utils/queue.h"

class pkt_worker : public QThread
{
        Q_OBJECT
    public:
        pkt_worker(queue_t *pkt_queue, QMutex *stop_mutex);
        virtual ~pkt_worker();
        virtual void start_work();
        virtual void stop_work();
    public:
        queue_t *pkt_queue;
        QMutex *stop_mutex;
        bool stop;
    private:
        virtual void run() = 0;

};

#endif // PKT_WORKER_H
