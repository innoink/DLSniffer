#include "pkt_processor.h"
#include <ctime>
#include <cstdio>
#include <cstring>

#include <QDebug>

pkt_processor::pkt_processor(queue_t *pkt_queue, QMutex *stop_mutex) :
    pkt_worker(pkt_queue, stop_mutex), pkt_cnt(0)
{
}
void pkt_deleter(void *pkt)
{
    Tins::Packet *pkt_ = (Tins::Packet *)pkt;
    delete pkt_;
}

void pkt_processor::run()
{
    Tins::Packet *pkt;
    pkt_cnt = 0;
    while (true) {
        stop_mutex->lock();
        if (stop) {
            stop_mutex->unlock();
            break;
        }
        stop_mutex->unlock();
        queue_get_wait(pkt_queue, (void **)&pkt);
        proc_pkt(pkt);
        delete pkt;
    }
    queue_flush_complete(pkt_queue, pkt_deleter);

}


void pkt_processor::proc_pkt(Tins::Packet *pkt)
{
    static struct pkt_info_t *pkt_info;
    static Tins::PDU         *pdu;
    static Tins::PDU::PDUType pdutype;

    static Tins::Timestamp    tv;
    static const char        *src, *dst, *prot;
    static size_t             size;
    static uint8_t            max_layer;

    pkt_info = new struct pkt_info_t;
    pdu      = pkt->pdu();
    tv       = pkt->timestamp();
    size     = pdu->size();

    pdutype  = pdu->pdu_type();

    //Layer I
    pkt_info->LayerI.Frame.size = size;
    max_layer = 1;
    //Layer II
    if (pdutype == Tins::PDU::PDUType::ETHERNET_II) {
        static Tins::EthernetII *eiipdu;
        eiipdu = (Tins::EthernetII *)pdu;
        pkt_info->LayerIIType = pkt_info_t::layer_ii_type::EthernetII;
        strncpy(pkt_info->LayerII.EthernetII.eii_dst_addr,
                eiipdu->dst_addr().to_string().c_str(),
                31);
        pkt_info->LayerII.EthernetII.eii_dst_addr[31] = '\0';
        strncpy(pkt_info->LayerII.EthernetII.eii_src_addr,
                eiipdu->src_addr().to_string().c_str(),
                31);
        pkt_info->LayerII.EthernetII.eii_src_addr[31] = '\0';
        pkt_info->LayerII.EthernetII.eii_header_size  = eiipdu->header_size();
        pkt_info->LayerII.EthernetII.eii_trailer_size = eiipdu->trailer_size();
        pkt_info->LayerII.EthernetII.eii_type         = eiipdu->payload_type();

        pkt_info->LayerII.EthernetII.eii_data_offset  = 0;
        pkt_info->LayerII.EthernetII.eii_data_len     = pkt_info->LayerII.EthernetII.eii_header_size;

        src = pkt_info->LayerII.EthernetII.eii_src_addr;
        dst = pkt_info->LayerII.EthernetII.eii_dst_addr;
        prot = "EthernetII";

    } else {
        fprintf(stderr, "pdutype : %d\n", pdutype);
        goto proc_failed;
    }
    max_layer = 2;
    pdu = pdu->inner_pdu();
    pdutype = pdu->pdu_type();
    if (pdu == nullptr)
        goto proc_success;
    //if (pdutype == Tins::PDU::PDUType::IP) ...



proc_success:
    PKT_INFO_SET_TIMESTR(pkt_info, __timestamp_to_str(tv));
    PKT_INFO_SET_SRC(pkt_info, src);
    PKT_INFO_SET_DST(pkt_info, dst);
    PKT_INFO_SET_PROTOCOL(pkt_info, prot);
    PKT_INFO_SET_SIZE(pkt_info, size);
    PKT_INFO_SET_MAX_LAYER(pkt_info, max_layer);
    PKT_INFO_SET_DATA(pkt_info, pkt->pdu()->serialize());
    emit new_pkt(pkt_info);
    return;
proc_failed:
    delete pkt_info;
    return;


}

const char *pkt_processor::__timestamp_to_str(Tins::Timestamp &timestamp)
{
    time_t sec_tv = timestamp.seconds();
    struct tm *localtm = std::localtime(&sec_tv);
    static char tmpstr[64];
    memset(tmpstr, 0x0, sizeof(tmpstr));
    std::strftime(tmpstr, 31, "%F %T", localtm);
    std::snprintf(tmpstr + strlen(tmpstr), 31, " %lu ms %lu us",
                  (unsigned long)timestamp.microseconds() / 1000,
                  (unsigned long)timestamp.microseconds() % 1000);
    return tmpstr;
}
