#ifndef PKT_INFO_H
#define PKT_INFO_H
#include <tins/tins.h>
#include <cstdint>
#include <QHash>
#include <QList>
#include <QPair>

struct pkt_info_t {
    Tins::Timestamp     timestamp;
    enum pdu_type_t {
        EthernetII,
        ARP,
        IP,
        ICMP,
        TCP,
        UDP,
        HTTP,
        HTTPS,
        FTP,
        TELNET,
        DNS,
        SMTP,
        POP3,
        IMAP,
        SNMP,
        UNKNOWN_TCP,
        UNKNOWN_UDP,
        UNKNOWN
    } top_pdu_type;
    struct {
        Tins::RawPDU       *raw_pdu;
        Tins::EthernetII   *eii_pdu;
    } pdus;
    QHash<enum pdu_type_t, Tins::PDU *> pdu_hash;
    QList<QPair<enum pdu_type_t, Tins::PDU *> > pdu_list;
    struct {
        char            timestampstr[64];
        char            src[32];
        char            dst[32];
        char            protocol[16];
        uint32_t        size;
    } overview;
};

typedef struct pkt_info_t pkt_info_t;

#endif // PKT_INFO_H
