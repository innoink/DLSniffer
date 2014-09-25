#include "ui/mainwindow.h"
#include "ui/select_nif_dlg.h"
#include <QApplication>

#include <iostream>

int main(int argc, char *argv[])
{
    std::cout << Tins::PDU::PDUType::RAW << std::endl;
    std::cout << Tins::PDU::PDUType::ETHERNET_II << std::endl;

//    QApplication a(argc, argv);
//    MainWindow w;
//    w.show();

//    return a.exec();
    return 0;
}
