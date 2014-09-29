#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QToolBar>
#include <QAction>
#include <QList>
#include "ui/pkt_list_view.h"
#include "ui/pkt_tree_view.h"
#include "ui/select_nif_dlg.h"
#include "sniffer/sniffer_manager.h"
#include "sniffer/pkt_info.h"

class MainWindow : public QMainWindow
{
        Q_OBJECT

    public:
        MainWindow(QWidget *parent = 0);
        ~MainWindow();

        void rcv_pkt_info(pkt_info_t *pkt_info);

    private:
        void create_toolbars();
        void create_actions();
        //slots:
        void select_nif();
        void start();
        void stop();
        void proc_selected_item(const QItemSelection & selected,
                                const QItemSelection & deselected);

    private:
        sniffer_manager *smgr;
        int current_pkt_num;

        pkt_list_view *lv;
        pkt_tree_view *tv;
        QToolBar *tb_work;

        QAction *act_start;
        QAction *act_stop;
        QAction *act_select_nif;
};

#endif // MAINWINDOW_H
