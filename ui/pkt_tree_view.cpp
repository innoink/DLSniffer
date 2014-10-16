#include <QStandardItem>
#include <QString>

#include "pkt_tree_view.h"

pkt_tree_view::pkt_tree_view(QWidget *parent) :
    QTreeView(parent)
{
    model = new QStandardItemModel;
    set_header();

    item_maker.insert(pkt_info_t::EthernetII, reinterpret_cast<item_maker_t>(pkt_tree_view::__new_eii_item));
    item_maker.insert(pkt_info_t::ARP, reinterpret_cast<item_maker_t>(pkt_tree_view::__new_arp_item));
    item_maker.insert(pkt_info_t::IP, reinterpret_cast<item_maker_t>(pkt_tree_view::__new_ip_item));
    item_maker.insert(pkt_info_t::ICMP, reinterpret_cast<item_maker_t>(pkt_tree_view::__new_icmp_item));
    item_maker.insert(pkt_info_t::TCP, reinterpret_cast<item_maker_t>(pkt_tree_view::__new_tcp_item));
    item_maker.insert(pkt_info_t::UDP, reinterpret_cast<item_maker_t>(pkt_tree_view::__new_udp_item));


    this->setModel(model);
}

void pkt_tree_view::set_header()
{
    model->setColumnCount(1);
    model->setHeaderData(0, Qt::Horizontal, tr("Packet Info"));
}
void pkt_tree_view::clear()
{
    model->clear();
    set_header();
}

void pkt_tree_view::add_pkt_info_item(pkt_info_t *pi)
{
    QStandardItem *item_root;

    for (QPair<enum pkt_info_t::pdu_type_t, Tins::PDU *> i : pi->pdu_list) {
        if (!item_maker.contains(i.first))
            continue;
        item_root = (item_maker.value(i.first))(i.second);
        model->appendRow(item_root);
        setExpanded(model->indexFromItem(item_root), true);
    }
}

QStandardItem *pkt_tree_view::__new_eii_item(Tins::EthernetII* eii_pdu)
{

    static QStandardItem *eii_item;
    static QStandardItem *child_item;
    eii_item = new QStandardItem;
    eii_item->setText(QString("Ethernet II - size %1 bytes").arg(eii_pdu->size()));
    child_item = new QStandardItem;
    child_item->setText(QString("Source Address: %1").arg(eii_pdu->src_addr().to_string().data()));
    eii_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("Destination Address: %1").arg(eii_pdu->dst_addr().to_string().data()));
    eii_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("Header Size: %1").arg(eii_pdu->header_size()));
    eii_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("Trailer Size: %1").arg(eii_pdu->trailer_size()));
    eii_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("Type: %1").arg(eii_pdu->payload_type()));
    eii_item->appendRow(child_item);
    return eii_item;
}

QStandardItem *pkt_tree_view::__new_arp_item(Tins::ARP *arp_pdu)
{
    static QStandardItem *arp_item;
    static QStandardItem *child_item;

    arp_item = new QStandardItem;
    arp_item->setText(QString("ARP - size %1 bytes").arg(arp_pdu->size()));

    child_item = new QStandardItem;
    child_item->setText(QString("Hardware Type: %1").arg(arp_pdu->hw_addr_format()));
    arp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("Hardware Size: %1").arg(arp_pdu->hw_addr_length()));
    arp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("Protocol Type: %1").arg(arp_pdu->prot_addr_format()));
    arp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("Protocol Size: %1").arg(arp_pdu->prot_addr_length()));
    arp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("Opcode: %1").arg(arp_pdu->opcode()));
    arp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("Sender MAC: %1").arg(arp_pdu->sender_hw_addr().to_string().data()));
    arp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("Sender IP: %1").arg(arp_pdu->sender_ip_addr().to_string().data()));
    arp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("Target MAC: %1").arg(arp_pdu->target_hw_addr().to_string().data()));
    arp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("Target IP: %1").arg(arp_pdu->target_ip_addr().to_string().data()));
    arp_item->appendRow(child_item);
    return arp_item;
}

QStandardItem *pkt_tree_view::__new_ip_item(Tins::IP *ip_pdu)
{
    static QStandardItem *ip_item;
    static QStandardItem *child_item;

    ip_item = new QStandardItem;
    ip_item->setText(QString("IP - size %1 bytes").arg(ip_pdu->size()));

    child_item = new QStandardItem;
    child_item->setText(QString("Version: %1").arg(ip_pdu->version()));
    ip_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Header Length: %1")).arg(ip_pdu->head_len()));
    ip_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Type Of Service: %1")).arg(ip_pdu->tos()));
    ip_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Total Length: %1")).arg(ip_pdu->tot_len()));
    ip_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Identification: %1")).arg(ip_pdu->id()));
    ip_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Fragmented: %1")).arg(ip_pdu->is_fragmented()));
    ip_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("TTL: %1")).arg(ip_pdu->ttl()));
    ip_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Protocol: %1")).arg(ip_pdu->protocol()));
    ip_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Checksum: %1")).arg(ip_pdu->checksum()));
    ip_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Source: %1")).arg(ip_pdu->src_addr().to_string().data()));
    ip_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Destination: %1")).arg(ip_pdu->dst_addr().to_string().data()));
    ip_item->appendRow(child_item);

    return ip_item;
}

QStandardItem *pkt_tree_view::__new_tcp_item(Tins::TCP *tcp_pdu)
{
    static QStandardItem *tcp_item;
    static QStandardItem *child_item;

    tcp_item = new QStandardItem;
    tcp_item->setText(QString("TCP - size %1 bytes").arg(tcp_pdu->size()));

    child_item = new QStandardItem;
    child_item->setText(QString(tr("Source Port: %1")).arg(tcp_pdu->sport()));
    tcp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Destination Port: %1")).arg(tcp_pdu->dport()));
    tcp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Sequence Number: %1")).arg(tcp_pdu->seq()));
    tcp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Acknowledgment Number: %1")).arg(tcp_pdu->ack_seq()));
    tcp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Header Length: %1")).arg(tcp_pdu->header_size()));
    tcp_item->appendRow(child_item);

    QStandardItem *tcp_flags_item = new QStandardItem;
    tcp_flags_item->setText(QString(tr("Flags:")));
    child_item = new QStandardItem;
    child_item->setText(QString(tr("FIN: %1")).arg(tcp_pdu->get_flag(Tins::TCP::FIN)));
    tcp_flags_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("SYN: %1")).arg(tcp_pdu->get_flag(Tins::TCP::SYN)));
    tcp_flags_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("RST: %1")).arg(tcp_pdu->get_flag(Tins::TCP::RST)));
    tcp_flags_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("PSH: %1")).arg(tcp_pdu->get_flag(Tins::TCP::PSH)));
    tcp_flags_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("ACK: %1")).arg(tcp_pdu->get_flag(Tins::TCP::ACK)));
    tcp_flags_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("URG: %1")).arg(tcp_pdu->get_flag(Tins::TCP::URG)));
    tcp_flags_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("ECE: %1")).arg(tcp_pdu->get_flag(Tins::TCP::ECE)));
    tcp_flags_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("CWR: %1")).arg(tcp_pdu->get_flag(Tins::TCP::CWR)));
    tcp_flags_item->appendRow(child_item);
    //setExpanded(model->indexFromItem(tcp_flags_item), true);
    tcp_item->appendRow(tcp_flags_item);

    child_item = new QStandardItem;
    child_item->setText(QString(tr("Window Size: %1")).arg(tcp_pdu->window()));
    tcp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Checksum: %1")).arg(tcp_pdu->checksum()));
    tcp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Urgent Ptr: %1")).arg(tcp_pdu->urg_ptr()));
    tcp_item->appendRow(child_item);




    return tcp_item;
}

QStandardItem *pkt_tree_view::__new_udp_item(Tins::UDP *udp_pdu)
{
    static QStandardItem *udp_item;
    static QStandardItem *child_item;

    udp_item = new QStandardItem;
    udp_item->setText(QString("UDP - size %1 bytes").arg(udp_pdu->size()));
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Source Port: %1")).arg(udp_pdu->sport()));
    udp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Destination Port: %1")).arg(udp_pdu->dport()));
    udp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Length: %1")).arg(udp_pdu->length()));
    udp_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString(tr("Checksum: %1")).arg(udp_pdu->checksum()));
    udp_item->appendRow(child_item);

    return udp_item;
}


QStandardItem *pkt_tree_view::__new_icmp_item(Tins::ICMP *icmp_pdu)
{
    static QStandardItem *icmp_item;
    static QStandardItem *child_item;

    icmp_item = new QStandardItem;
    icmp_item->setText(QString("ICMP - size %1 bytes").arg(icmp_pdu->size()));

    //..

    return icmp_item;
}
