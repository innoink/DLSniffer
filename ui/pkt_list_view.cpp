#include "pkt_list_view.h"

pkt_list_view::pkt_list_view(QWidget *parent) :
    QTreeView(parent), item_cnt(0)
{
    model = new QStandardItemModel;
    set_header();
    this->setModel(model);
}

void pkt_list_view::set_header()
{
    model->setColumnCount(6);
    model->setHeaderData(0, Qt::Horizontal, tr("No."));
    model->setHeaderData(1, Qt::Horizontal, tr("Time"));
    model->setHeaderData(2, Qt::Horizontal, tr("Source Address"));
    model->setHeaderData(3, Qt::Horizontal, tr("Target Address"));
    model->setHeaderData(4, Qt::Horizontal, tr("Protocol"));
    model->setHeaderData(5, Qt::Horizontal, tr("Packet Size"));
}

void pkt_list_view::append_item(int num, const char *timestr, const char *srcaddr, const char *dstaddr,
                                const char *prot, uint32_t size)
{
    static QStandardItem *item;

    item = new QStandardItem(QString::number(num));
    model->setItem(item_cnt, 0, item);
    item = new QStandardItem(timestr);
    model->setItem(item_cnt, 1, item);
    item = new QStandardItem(srcaddr);
    model->setItem(item_cnt, 2, item);
    item = new QStandardItem(dstaddr);
    model->setItem(item_cnt, 3, item);
    item = new QStandardItem(prot);
    model->setItem(item_cnt, 4, item);
    item = new QStandardItem(QString::number(size));
    model->setItem(item_cnt, 5, item);

    item_cnt++;
}

void pkt_list_view::clear()
{
    model->clear();
    item_cnt = 0;
    set_header();
}

int pkt_list_view::get_item_num(QModelIndex &index)
{
    return model->data(index, 0).toString().toInt();
}
