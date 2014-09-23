#include "mainwindow.h"
#include <QHBoxLayout>
#include <QPushButton>
#include <QSplitter>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    lv = new list_view(this);
    QSplitter *splitter = new QSplitter(this);
    splitter->addWidget(lv);
    setCentralWidget(splitter);
}

MainWindow::~MainWindow()
{

}
