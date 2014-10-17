#include "sniffer_list_view.h"

sniffer_list_view::sniffer_list_view(QWidget *parent) :
    QTreeView(parent), item_cnt(0)
{
    model = new QStandardItemModel;
    set_header();
    this->setModel(model);
}

void sniffer_list_view::set_header()
{
    model->setColumnCount(5);
    model->setHeaderData(0, Qt::Horizontal, tr("No."));
    model->setHeaderData(1, Qt::Horizontal, tr("Protocol"));
    model->setHeaderData(2, Qt::Horizontal, tr("Site"));
    model->setHeaderData(3, Qt::Horizontal, tr("Username"));
    model->setHeaderData(4, Qt::Horizontal, tr("Password"));
}

void sniffer_list_view::append_item(const QString &protocol, const QString &site, const QString &username, const QString &password)
{
    static QStandardItem *item;

    item = new QStandardItem(QString::number(item_cnt));
    model->setItem(item_cnt, 0, item);
    item = new QStandardItem(protocol);
    model->setItem(item_cnt, 1, item);
    item = new QStandardItem(site);
    model->setItem(item_cnt, 2, item);
    item = new QStandardItem(username);
    model->setItem(item_cnt, 3, item);
    item = new QStandardItem(password);
    model->setItem(item_cnt, 4, item);

    item_cnt++;
}

void sniffer_list_view::clear()
{
    model->clear();
    item_cnt = 0;
    set_header();
}
