#ifndef PROTOCOL_SNIFFERS_H
#define PROTOCOL_SNIFFERS_H

#include <tins/tins.h>
#include <QList>
#include <QString>
#include <QObject>

class sniffer_result :public QObject
{
    Q_OBJECT
signals:
    void new_sniffer_result(const QString &protocol, const QString &site, const QString &username, const QString &password);
};


class protocol_sniffers {

public:
    static sniffer_result sresult;
static void http_sniffer(const Tins::PDU *http_pdu);
};

#endif // PROTOCOL_SNIFFERS_H
