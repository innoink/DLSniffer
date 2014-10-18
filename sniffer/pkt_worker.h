#ifndef PKT_WORKER_H
#define PKT_WORKER_H

#include <QThread>
#include <atomic>
#include "utils/queue.h"

class pkt_worker : public QThread
{
        Q_OBJECT
    public:
        pkt_worker(queue_t *pkt_queue);
        virtual ~pkt_worker();
        virtual void start_work();
        virtual void stop_work();
    public:
        queue_t *pkt_queue;
    private:
        virtual void run() = 0;
    protected:
        std::atomic_bool stop;
};

#endif // PKT_WORKER_H
