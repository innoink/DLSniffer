#include "mainwindow.h"
#include <QHBoxLayout>
#include <QPushButton>
#include <QSplitter>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    smgr = new sniffer_manager;

    lv = new pkt_list_view(this);
    QSplitter *splitter = new QSplitter(this);
    splitter->addWidget(lv);
    setCentralWidget(splitter);

    create_actions();
    create_toolbars();

    connect(smgr->pp_thrd, &pkt_processor::new_pkt, lv, &pkt_list_view::add_pkt_info);
}

MainWindow::~MainWindow()
{

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

