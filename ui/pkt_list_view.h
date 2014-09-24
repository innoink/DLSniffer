#ifndef PKT_LIST_VIEW_H
#define PKT_LIST_VIEW_H

#include <QTreeView>
#include <QStandardItemModel>
#include "sniffer/pkt_processor.h"

class pkt_list_view : public QTreeView
{
        Q_OBJECT
    public:
        explicit pkt_list_view(QWidget *parent = 0);
        void set_header();
        void clear();

    signals:

    public slots:
        void add_pkt_info(struct pkt_info_t *pkt_info);
    private:
        unsigned item_cnt;
        QStandardItemModel *model;

};

#endif // PKT_LIST_VIEW_H
