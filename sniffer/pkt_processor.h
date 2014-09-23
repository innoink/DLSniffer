#ifndef PKT_PROCESSOR_H
#define PKT_PROCESSOR_H

#include <QObject>

class pkt_processor : public QObject
{
        Q_OBJECT
    public:
        explicit pkt_processor(QObject *parent = 0);

    signals:

    public slots:

};

#endif // PKT_PROCESSOR_H
