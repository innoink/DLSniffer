#include <QStandardItem>
#include <QString>

#include "pkt_tree_view.h"

pkt_tree_view::pkt_tree_view(QWidget *parent) :
    QTreeView(parent)
{
    model = new QStandardItemModel;
    set_header();

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
    item_root = __new_eii_item(pi->pdus.eii_pdu);
    model->appendRow(item_root);
    setExpanded(model->indexFromItem(item_root), true);
    if (pi->top_pdu_type == pkt_info_t::ARP) {
        item_root = __new_arp_item((Tins::ARP*)(pi->pdus.eii_pdu->inner_pdu()));
        model->appendRow(item_root);
        setExpanded(model->indexFromItem(item_root), true);
    } else {
        Tins::IP *ip_pdu = (Tins::IP*)(pi->pdus.eii_pdu->inner_pdu());
        item_root = __new_ip_item(ip_pdu);
        model->appendRow(item_root);
        setExpanded(model->indexFromItem(item_root), true);
    }
}

QStandardItem *pkt_tree_view::__new_eii_item(Tins::EthernetII *eii_pdu)
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
//...
    return ip_item;
}
