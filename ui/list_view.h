#ifndef LIST_VIEW_H
#define LIST_VIEW_H

#include <QTreeView>
#include <QStandardItemModel>

class list_view : public QTreeView
{
        Q_OBJECT
    public:
        explicit list_view(QWidget *parent = 0);

    signals:

    public slots:
    private:
        unsigned item_cnt;
        QStandardItemModel *model;

};

#endif // LIST_VIEW_H
