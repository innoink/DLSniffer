#ifndef PKT_CAPTURE_H
#define PKT_CAPTURE_H

#include <QObject>
#include <tins/tins.h>
#include "utils/queue.h"

class pkt_capture : public QObject
{
        Q_OBJECT
    public:
        explicit pkt_capture(queue_t *q);

    signals:

    public slots:
    private:
        queue_t *pkt_queue;

};

#endif // PKT_CAPTURE_H
