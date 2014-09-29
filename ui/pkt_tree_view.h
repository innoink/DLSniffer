#ifndef PKT_TREE_VIEW_H
#define PKT_TREE_VIEW_H

#include <QTreeView>
#include <QStandardItemModel>
#include <tins/tins.h>
#include "sniffer/pkt_info.h"

class pkt_tree_view : public QTreeView
{
        Q_OBJECT
    public:
        explicit pkt_tree_view(QWidget *parent = 0);
        void add_pkt_info_item(struct pkt_info_t *pi);
        void clear();

    private:
        void set_header();
        QStandardItem *__new_eii_item(Tins::EthernetII *eii_pdu);
        QStandardItem *__new_arp_item(Tins::ARP *arp_pdu);
        QStandardItem *__new_ip_item(Tins::IP *ip_pdu);
        QStandardItem *__new_icmp_item(Tins::ICMP *icmp_pdu);
        QStandardItem *__new_tcp_item(Tins::TCP *tcp_pdu);
        QStandardItem *__new_udp_item(Tins::UDP *udp_pdu);
        QStandardItem *__new_app_item(Tins::RawPDU *raw_pdu);

    private:
        QStandardItemModel *model;

};

#endif // PKT_TREE_VIEW_H
