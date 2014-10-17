#ifndef SNIFFER_LIST_VIEW_H
#define SNIFFER_LIST_VIEW_H

#include <QTreeView>
#include <QString>
#include <QStandardItemModel>

class sniffer_list_view : public QTreeView
{
    Q_OBJECT
public:
    explicit sniffer_list_view(QWidget *parent = 0);
    void set_header();
    void clear();
    void append_item(const QString &protocol, const QString &site, const QString &username, const QString &password);

private:
    unsigned item_cnt;
    QStandardItemModel *model;

};

#endif // SNIFFER_LIST_VIEW_H
