#ifndef SNIFFER_MANAGER_H
#define SNIFFER_MANAGER_H

#include <QObject>
#include <tins/tins.h>
#include "utils/queue.h"
#include "pkt_capture.h"
#include "pkt_processor.h"


class sniffer_manager : public QObject
{
        Q_OBJECT
    public:
        explicit sniffer_manager(QObject *parent = 0);
        void start_capture();
        void stop_capture();
        void set_filter();
        void set_interface();

    signals:

    public slots:
    private:
        Tins::SnifferConfiguration sconf;
        queue_t *pkt_queue;

};

#endif // SNIFFER_MANAGER_H
