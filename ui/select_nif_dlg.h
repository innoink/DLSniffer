#ifndef SELECT_NIF_DLG_H
#define SELECT_NIF_DLG_H

#include <QDialog>
#include <QListView>
#include <QStandardItemModel>
#include <QDialogButtonBox>
#include <QCheckBox>
#include <QLineEdit>
#include <tins/tins.h>
#include <vector>
#include <QPushButton>
#include <QGroupBox>

class select_nif_dlg : public QDialog
{
        Q_OBJECT
    public:
        explicit select_nif_dlg(QWidget *parent = 0);
        Tins::NetworkInterface get_selected();
        bool use_promisc();
        QString get_filter();
        bool use_http_sniffer();
        bool use_ftp_sniffer();

    signals:

    private slots:
        void set_choose(QStandardItem *item);
    private:
        void setup_nif_info();
    private:

        QListView *nif_list_view;
        QStandardItemModel *model;
        QCheckBox *cb_promisc;
        QDialogButtonBox *btnbox;
        QPushButton *btnok;
        QPushButton *btncancle;
        QLineEdit *leflt;

        QGroupBox *gb_sniffers;
        QCheckBox *cb_http, *cb_ftp;

        std::vector<Tins::NetworkInterface> all_nif;
        int selected;
};

#endif // SELECT_NIF_DLG_H
