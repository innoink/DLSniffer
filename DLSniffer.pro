#-------------------------------------------------
#
# Project created by QtCreator 2014-09-13T10:50:52
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = DLSniffer
TEMPLATE = app
LIBS += -ltins
CONFIG += c++11

SOURCES += main.cpp\
        mainwindow.cpp \
    capture.cpp \
    list_view.cpp

HEADERS  += mainwindow.h \
    capture.h \
    list_view.h
