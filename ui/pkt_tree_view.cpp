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
