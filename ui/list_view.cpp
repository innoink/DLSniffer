#include "list_view.h"

list_view::list_view(QWidget *parent) :
    QTreeView(parent), item_cnt(0)
{
    model = new QStandardItemModel;

    model->setColumnCount(6);
    model->setHeaderData(0, Qt::Horizontal, tr("序号"));
    model->setHeaderData(1, Qt::Horizontal, tr("时间"));
    model->setHeaderData(2, Qt::Horizontal, tr("来源IP地址"));
    model->setHeaderData(3, Qt::Horizontal, tr("目标IP地址"));
    model->setHeaderData(4, Qt::Horizontal, tr("协议"));
    model->setHeaderData(5, Qt::Horizontal, tr("发送长度"));

    this->setModel(model);
}
