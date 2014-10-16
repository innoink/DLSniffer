#ifndef PROTOCOL_SNIFFERS_H
#define PROTOCOL_SNIFFERS_H

#include <tins/tins.h>
#include <QList>
#include <QString>


class protocol_sniffers {
    typedef struct http_password_t {
        QString site_url;
        QString username;
        QString password;
    } http_password_t;

public:
static void http_sniffer(const Tins::PDU *http_pdu);
static QList<http_password_t> http_param;
};

#endif // PROTOCOL_SNIFFERS_H
