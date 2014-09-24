#include "ui/mainwindow.h"
#include "ui/select_nif_dlg.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
//    select_nif_dlg dlg(0, 0);
//    dlg.exec();

    return a.exec();
}
