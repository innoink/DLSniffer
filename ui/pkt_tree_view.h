#ifndef PKT_TREE_VIEW_H
#define PKT_TREE_VIEW_H

#include <QTreeView>

class pkt_tree_view : public QTreeView
{
        Q_OBJECT
    public:
        explicit pkt_tree_view(QTreeView *parent = 0);

    signals:

    public slots:

};

#endif // PKT_TREE_VIEW_H
