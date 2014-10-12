#include "mainwindow.h"
#include <QHBoxLayout>
#include <QPushButton>
#include <QSplitter>
#include <QMessageBox>
#include <QBuffer>
#include "sniffer/dlsniffer_defs.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    smgr = new sniffer_manager;

    lv = new pkt_list_view(this);
    tv = new pkt_tree_view(this);
    hex_view = new QHexView(this);
    QSplitter *splitter = new QSplitter(this);
    QSplitter *splitter_2 = new QSplitter(Qt::Vertical);
    splitter->addWidget(lv);
    splitter_2->addWidget(tv);
    splitter_2->addWidget(hex_view);
    splitter->addWidget(splitter_2);
    setCentralWidget(splitter);

    create_actions();
    create_toolbars();

    smgr->set_filter(DLSNIFFER_FILTER);

    connect(smgr->pp_thrd, &pkt_processor::new_pkt_info, this, &MainWindow::rcv_pkt_info);
    connect(lv->selectionModel(), &QItemSelectionModel::selectionChanged, this, &MainWindow::proc_selected_item);
}

MainWindow::~MainWindow()
{
    delete smgr;
}

void MainWindow::create_actions()
{
    act_select_nif = new QAction(tr("Interfaces"), this);
    act_select_nif->setStatusTip(tr("Select Network Interface To Start Sniffer"));
    connect(act_select_nif, &QAction::triggered, this, &MainWindow::select_nif);

    act_start = new QAction(tr("Start"), this);
    act_start->setStatusTip(tr("Start Capture"));
    act_start->setEnabled(false);
    connect(act_start, &QAction::triggered, this, &MainWindow::start);

    act_stop = new QAction(tr("Stop"), this);
    act_stop->setStatusTip(tr("Stop Capture"));
    act_stop->setEnabled(false);
    connect(act_stop, &QAction::triggered, this, &MainWindow::stop);
}

void MainWindow::create_toolbars()
{
    tb_work = addToolBar(tr("Capture"));
    tb_work->addAction(act_select_nif);
    tb_work->addSeparator();
    tb_work->addAction(act_start);
    tb_work->addAction(act_stop);

}

//SLOTS
void MainWindow::select_nif()
{
    select_nif_dlg sndlg(this);

    if (sndlg.exec() == QDialog::Accepted) {
        smgr->set_nif(sndlg.get_selected());
        smgr->set_promisc(sndlg.use_promisc());
        if (!smgr->init_sniffer()) {
            QMessageBox::warning(this, tr("Sniffer"),
                                 QString(tr("Cannot init sniffer on ")).append(smgr->get_nif().name().c_str()),
                                 QMessageBox::Ok);
            return;
        }
        act_start->setEnabled(true);
    }
}

void MainWindow::start()
{
    lv->clear();
    tv->clear();
    smgr->destroy_pkt_info_list();
    smgr->start_capture();
    act_start->setEnabled(false);
    act_stop->setEnabled(true);
}

void MainWindow::stop()
{
    smgr->stop_capture();
    act_stop->setEnabled(false);
    act_start->setEnabled(true);
}

void MainWindow::rcv_pkt_info(pkt_info_t *pkt_info)
{
    lv->append_item(pkt_info->overview.timestampstr,
                    pkt_info->overview.src,
                    pkt_info->overview.dst,
                    pkt_info->overview.protocol,
                    pkt_info->overview.size);
    smgr->pkt_info_list.append(pkt_info);
}

void MainWindow::proc_selected_item(const QItemSelection &selected, const QItemSelection &deselected)
{
    static QByteArray ba;
    static QBuffer buf;
    tv->clear();
    hex_view->clear();

    QModelIndexList items = selected.indexes();
    QModelIndex     index = items.first();
    current_pkt_num = lv->get_item_num(index);
    if (current_pkt_num >= 0 && current_pkt_num <= smgr->pkt_info_list.size()) {
        tv->add_pkt_info_item(smgr->pkt_info_list[current_pkt_num]);
        ba.clear();
        ba.append((const char*)(smgr->pkt_info_list[current_pkt_num]->pdus.raw_pdu->payload().data()),
                      smgr->pkt_info_list[current_pkt_num]->pdus.raw_pdu->payload().size());
        if (buf.isOpen()) {
            buf.close();
        }
        buf.setData(ba);
        buf.open(QIODevice::ReadOnly);
        hex_view->setData(&buf);
    }
}
