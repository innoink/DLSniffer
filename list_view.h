#ifndef LIST_VIEW_H
#define LIST_VIEW_H

#include <QTreeView>

class list_view : public QTreeView
{
        Q_OBJECT
    public:
        explicit list_view(QWidget *parent = 0);

    signals:

    public slots:

};

#endif // LIST_VIEW_H
