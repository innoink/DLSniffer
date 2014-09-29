#ifndef PKT_LIST_VIEW_H
#define PKT_LIST_VIEW_H

#include <QTreeView>
#include <QStandardItemModel>
#include "sniffer/pkt_info.h"

class pkt_list_view : public QTreeView
{
        Q_OBJECT
    public:
        explicit pkt_list_view(QWidget *parent = 0);
        void set_header();
        void clear();
        void append_item(const char *timestr, const char *srcaddr, const char *dstaddr,
                         const char *prot, uint32_t size);

        int get_item_num(QModelIndex &index);
    private:
        unsigned item_cnt;
        QStandardItemModel *model;

};

#endif // PKT_LIST_VIEW_H
