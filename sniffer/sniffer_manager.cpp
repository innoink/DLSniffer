#include "sniffer_manager.h"

sniffer_manager::sniffer_manager(QObject *parent) :
    QObject(parent)
{
    pkt_queue = queue_create();
}
