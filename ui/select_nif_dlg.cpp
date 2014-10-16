#include "select_nif_dlg.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>

select_nif_dlg::select_nif_dlg(QWidget *parent) :
    QDialog(parent), selected(0)
{
    this->nif_list_view = new QListView;
    this->cb_promisc = new QCheckBox(tr("promisc mode"));
    this->btnbox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    this->btnok = btnbox->button(QDialogButtonBox::Ok);
    this->btncancle = btnbox->button(QDialogButtonBox::Cancel);
    this->leflt = new QLineEdit;
    this->model = new QStandardItemModel;

    QVBoxLayout *vl = new QVBoxLayout(this);
    QHBoxLayout *hl = new QHBoxLayout;
    hl->addWidget(new QLabel(tr("Filter:")));
    hl->addWidget(leflt);
    vl->addWidget(nif_list_view);
    vl->addWidget(cb_promisc);
    vl->addLayout(hl);
    vl->addWidget(btnbox);

    btnok->setEnabled(false);
    this->setup_nif_info();

    connect(btnbox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(btnbox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(model, &QStandardItemModel::itemChanged, this, &select_nif_dlg::set_choose);
}

void select_nif_dlg::setup_nif_info()
{
    all_nif = Tins::NetworkInterface::all();
    for (auto &i : all_nif) {
        QStandardItem *item = new QStandardItem(i.name().c_str());
        item->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable|Qt::ItemIsUserCheckable);
        item->setCheckState(Qt::Unchecked);
        model->appendRow(item);
    }

    this->nif_list_view->setModel(model);
}

void select_nif_dlg::set_choose(QStandardItem *item)
{
    QStandardItem *tmpitem;
    btnok->setEnabled(false);
    if (item->checkState() == Qt::Checked) {
        for (int i = 0; i < model->rowCount(); i++) {
            tmpitem = model->item(i, 0);
            if (tmpitem != item)
                tmpitem->setCheckState(Qt::Unchecked);
            else
                selected = i;
        }
        btnok->setEnabled(true);
    }
}

Tins::NetworkInterface select_nif_dlg::get_selected()
{
    return all_nif[selected];
}

QString select_nif_dlg::get_filter()
{
    return this->leflt->text();
}

bool select_nif_dlg::use_promisc()
{
    return this->cb_promisc->isChecked();
}
