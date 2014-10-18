#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QToolBar>
#include <QAction>
#include <QList>
#include <QComboBox>
#include <QPushButton>
#include "ui/pkt_list_view.h"
#include "ui/pkt_tree_view.h"
#include "ui/select_nif_dlg.h"
#include "ui/sniffer_list_view.h"
#include "ui/QHexView/qhexview.h"
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
        void clear_view();
        void apply_flt();
        void clear_flt();
        void proc_selected_item(const QItemSelection & selected,
                                const QItemSelection & deselected);

    private:
        sniffer_manager *smgr;
        int current_pkt_num;

        pkt_list_view *plv;
        pkt_tree_view *ptv;
        sniffer_list_view *slv;

        QHexView      *hex_view;

        QToolBar *tb_work;

        QAction *act_start;
        QAction *act_stop;
        QAction *act_select_nif;
        QAction *act_clear;

        QComboBox *cb_post_flt;
        QPushButton *pb_apply_flt;
        QPushButton *pb_clear_flt;



};

#endif // MAINWINDOW_H
