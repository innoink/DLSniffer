#include "mainwindow.h"
#include <QHBoxLayout>
#include <QPushButton>
#include <QSplitter>
#include <QMessageBox>
#include <QBuffer>
#include <cstring>
#include "sniffer/dlsniffer_defs.h"
#include "sniffer/protocol_sniffers.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    smgr = new sniffer_manager;

    plv = new pkt_list_view(this);
    ptv = new pkt_tree_view(this);
    slv = new sniffer_list_view(this);
    hex_view = new QHexView(this);
    QSplitter *splitter = new QSplitter(this);
    QSplitter *splitter_left  = new QSplitter(Qt::Vertical);
    QSplitter *splitter_right = new QSplitter(Qt::Vertical);
    splitter_left->addWidget(plv);
    splitter_left->addWidget(slv);
    splitter_right->addWidget(ptv);
    splitter_right->addWidget(hex_view);
    splitter->addWidget(splitter_left);
    splitter->addWidget(splitter_right);
    setCentralWidget(splitter);

    create_actions();
    create_toolbars();

//    smgr->set_filter(DLSNIFFER_FILTER);

    connect(smgr->pp_thrd, &pkt_processor::new_pkt_info, this, &MainWindow::rcv_pkt_info);
    connect(&protocol_sniffers::sresult, &sniffer_result::new_sniffer_result, this->slv, &sniffer_list_view::append_item);
    connect(plv->selectionModel(), &QItemSelectionModel::selectionChanged, this, &MainWindow::proc_selected_item);

    //setWindowOpacity(0.5);
}

MainWindow::~MainWindow()
{
    delete smgr;
}

void MainWindow::create_actions()
{
    act_select_nif = new QAction(tr("Interfaces"), this);
    act_select_nif->setToolTip(tr("Select Network Interface To Start Sniffer"));
    connect(act_select_nif, &QAction::triggered, this, &MainWindow::select_nif);

    act_start = new QAction(tr("Start"), this);
    act_start->setToolTip(tr("Start Capture"));
    act_start->setEnabled(false);
    connect(act_start, &QAction::triggered, this, &MainWindow::start);

    act_stop = new QAction(tr("Stop"), this);
    act_stop->setToolTip(tr("Stop Capture"));
    act_stop->setEnabled(false);
    connect(act_stop, &QAction::triggered, this, &MainWindow::stop);

    act_clear = new QAction(tr("Clear"), this);
    act_clear->setToolTip(tr("Clear Result"));
    act_clear->setEnabled(false);
    connect(act_clear, &QAction::triggered, this, &MainWindow::clear_view);
}

void MainWindow::create_toolbars()
{
    tb_work = addToolBar(tr("Capture"));
    tb_work->addAction(act_select_nif);
    tb_work->addSeparator();
    tb_work->addAction(act_start);
    tb_work->addAction(act_stop);
    tb_work->addAction(act_clear);
    tb_work->addSeparator();

    cb_post_flt = new QComboBox;
    connect(cb_post_flt, &QComboBox::currentTextChanged,
            [=](const QString & text)
            {
                if (!text.isEmpty()) {
                    pb_apply_flt->setEnabled(true);
                    pb_clear_flt->setEnabled(false);
                }
            });
    cb_post_flt->setEditable(true);
    cb_post_flt->addItem(tr(""));
    cb_post_flt->addItem(tr("TCP"));
    cb_post_flt->addItem(tr("UDP"));
    cb_post_flt->addItem(tr("ARP"));
    cb_post_flt->addItem(tr("ICMP"));
    cb_post_flt->addItem(tr("HTTP"));
    cb_post_flt->addItem(tr("FTP"));
    pb_apply_flt = new QPushButton(tr("Apply"));
    pb_clear_flt = new QPushButton(tr("Clear"));
    connect(pb_apply_flt, &QPushButton::clicked, this, &MainWindow::apply_flt);
    connect(pb_clear_flt, &QPushButton::clicked, this, &MainWindow::clear_flt);
    pb_apply_flt->setEnabled(false);
    pb_clear_flt->setEnabled(false);
    tb_work->addWidget(cb_post_flt);
    tb_work->addWidget(pb_apply_flt);
    tb_work->addWidget(pb_clear_flt);

}

//SLOTS
void MainWindow::select_nif()
{
    select_nif_dlg sndlg(this);

    if (sndlg.exec() == QDialog::Accepted) {
        smgr->set_nif(sndlg.get_selected());
        smgr->set_promisc(sndlg.use_promisc());
        smgr->set_filter(sndlg.get_filter().toStdString().data());
        smgr->clear_sniffer();
        if (sndlg.use_http_sniffer()) {
            smgr->add_http_sniffer();
        }
        if (sndlg.use_ftp_sniffer()) {
            //add ftp sniffer...
        }
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
    clear_view();
    smgr->destroy_pkt_info_list();
    smgr->start_capture();
    act_select_nif->setEnabled(false);
    act_start->setEnabled(false);
    act_stop->setEnabled(true);
    act_clear->setEnabled(false);
    cb_post_flt->setEnabled(false);
    pb_apply_flt->setEnabled(false);
    pb_clear_flt->setEnabled(false);
}

void MainWindow::stop()
{
    smgr->stop_capture();
    act_select_nif->setEnabled(true);
    act_stop->setEnabled(false);
    act_start->setEnabled(true);
    act_clear->setEnabled(true);
    cb_post_flt->setEnabled(true);
}

void MainWindow::clear_view()
{
    plv->clear();
    ptv->clear();
    slv->clear();
    hex_view->clear();
}


void MainWindow::apply_flt()
{
    clear_view();
    QString fltstr = cb_post_flt->currentText();
    int pos = 0;
    for (pkt_info_t *i : smgr->pkt_info_list) {
        if (strcasestr(i->overview.protocol, fltstr.toStdString().data()) != nullptr) {
            plv->append_item(pos,
                            i->overview.timestampstr,
                            i->overview.src,
                            i->overview.dst,
                            i->overview.protocol,
                            i->overview.size);
        }
        ++pos;
    }
    pb_apply_flt->setEnabled(false);
    pb_clear_flt->setEnabled(true);
}

void MainWindow::clear_flt()
{
    clear_view();
    int pos = 0;
    for (pkt_info_t *i : smgr->pkt_info_list) {
        plv->append_item(pos++,
                        i->overview.timestampstr,
                        i->overview.src,
                        i->overview.dst,
                        i->overview.protocol,
                        i->overview.size);
    }
    cb_post_flt->setCurrentIndex(0);
    pb_clear_flt->setEnabled(false);
}

void MainWindow::rcv_pkt_info(pkt_info_t *pkt_info)
{
    plv->append_item(smgr->pkt_info_list.size(),
                    pkt_info->overview.timestampstr,
                    pkt_info->overview.src,
                    pkt_info->overview.dst,
                    pkt_info->overview.protocol,
                    pkt_info->overview.size);
    smgr->pkt_info_list.append(pkt_info);
}

void MainWindow::proc_selected_item(const QItemSelection &selected, const QItemSelection &deselected)
{
    Q_UNUSED(deselected);
    static QByteArray ba;
    static QBuffer buf;
    ptv->clear();
    hex_view->clear();

    QModelIndexList items = selected.indexes();
    QModelIndex     index = items.first();
    current_pkt_num = plv->get_item_num(index);
    if (current_pkt_num >= 0 && current_pkt_num <= smgr->pkt_info_list.size()) {
        ptv->add_pkt_info_item(smgr->pkt_info_list[current_pkt_num]);
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
