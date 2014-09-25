#ifndef SNIFFER_MANAGER_H
#define SNIFFER_MANAGER_H

#include <QObject>
#include <QMutex>
#include <tins/tins.h>
#include "utils/queue.h"
#include "pkt_capture.h"
#include "pkt_processor.h"


class sniffer_manager : public QObject
{
        Q_OBJECT
    public:
        explicit sniffer_manager(QObject *parent = 0);
        ~sniffer_manager();
        bool init_sniffer();
        void release_sniffer();
        void start_capture();
        void stop_capture();
        void set_filter(QString &flt);
        void set_nif(Tins::NetworkInterface nif);
        void set_promisc(bool b);
        Tins::NetworkInterface get_nif();
    signals:

    public slots:
    public:
        pkt_processor *pp_thrd;
    private:
        Tins::Sniffer *sniffer;
        Tins::SnifferConfiguration sconf;
        Tins::NetworkInterface nif;
        pkt_capture *pc_thrd;
        QMutex *pc_stopmutex, *pp_stopmutex;
        queue_t *pkt_queue;

};

#endif // SNIFFER_MANAGER_H
