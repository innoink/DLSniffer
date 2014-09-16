#ifndef CAPTURE_THREAD_H
#define CAPTURE_THREAD_H

#include <QObject>
#include <QString>
#include <tins/tins.h>

struct packet_info {
        Tins::PDU::PDUType type;
        Tins::Packet       *packet;
};

class capture_worker : public QObject
{
        Q_OBJECT
    public slots:
        void do_work();
    signals:
        void started();
        void stopped();
        void new_packet(Tins::Packet *packet);

};

class capture : public QObject
{
        Q_OBJECT
    public:
        explicit capture(QObject *parent = 0);

    signals:

    private slots:
        void process_packet(Tins::Packet *packet);
    private:
        void add_item();
    private:


};

#endif // CAPTURE_THREAD_H
