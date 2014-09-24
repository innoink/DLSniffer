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
    model->setHeaderData(0, Qt::Horizontal, tr("序号"));
    model->setHeaderData(1, Qt::Horizontal, tr("时间"));
    model->setHeaderData(2, Qt::Horizontal, tr("来源IP地址"));
    model->setHeaderData(3, Qt::Horizontal, tr("目标IP地址"));
    model->setHeaderData(4, Qt::Horizontal, tr("协议"));
    model->setHeaderData(5, Qt::Horizontal, tr("发送长度"));
}

void pkt_list_view::add_pkt_info(struct pkt_info_t *pkt_info)
{
    static QStandardItem *item;

    item = new QStandardItem(QString::number(pkt_info->pkt_num));
    model->setItem(item_cnt, 0, item);
    item = new QStandardItem(pkt_info->timestr);
    model->setItem(item_cnt, 1, item);
    item = new QStandardItem(pkt_info->srcip);
    model->setItem(item_cnt, 2, item);
    item = new QStandardItem(pkt_info->dstip);
    model->setItem(item_cnt, 3, item);

    item_cnt++;
    delete pkt_info;
}

void pkt_list_view::clear()
{
    model->clear();
    item_cnt = 0;
    set_header();
}
