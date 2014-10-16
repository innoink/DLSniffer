#include "pkt_processor.h"
#include <ctime>
#include <cstdio>
#include <cstring>
#include "sniffer/dlsniffer_defs.h"

#include <QDebug>

pkt_processor::pkt_processor(queue_t *pkt_queue, QReadWriteLock *stop_rwlock) :
    pkt_worker(pkt_queue, stop_rwlock), pkt_cnt(0)
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
        stop_rwlock->lockForRead();
        if (stop) {
            stop_rwlock->unlock();
            break;
        }
        stop_rwlock->unlock();
        queue_get_wait(pkt_queue, (void **)&pkt);
        if (pkt == nullptr)
            continue;
        proc_pkt(pkt);
        //printf("queue size:\t%d\n", queue_elements(pkt_queue));
        delete pkt;
    }
    queue_flush_complete(pkt_queue, pkt_deleter);

}

void pkt_processor::proc_pkt(Tins::Packet *pkt)
{
    static Tins::RawPDU *raw_pdu;
    static struct pkt_info_t *pkt_info;
    pkt_info = nullptr;

    //get the inner raw pdu, then set pkt->pdu to null.
    raw_pdu = (Tins::RawPDU *)(pkt->release_pdu());
    //LayerII
    Tins::EthernetII *eii_pdu;
    bool              is_eii;
    //is EthernetII?
    try {
        //use move constructor
        eii_pdu = new Tins::EthernetII(raw_pdu->to<Tins::EthernetII>());
        is_eii  = true;
    } catch (...) {
        is_eii = false;
    }
    if (!is_eii)
        goto proc_failed;

    pkt_info = new struct pkt_info_t;
    pkt_info->pdus.raw_pdu = raw_pdu;
    pkt_info->pdus.eii_pdu = eii_pdu;
    pkt_info->pdu_hash.insert(pkt_info_t::EthernetII, eii_pdu);
    pkt_info->pdu_list.append(QPair<enum pkt_info_t::pdu_type_t, Tins::PDU*>(pkt_info_t::EthernetII, eii_pdu));
    //check valid pdu
    static Tins::PDU *pdu;
    pdu = eii_pdu;
    if (pdu->inner_pdu() == nullptr)
        goto proc_failed;
    pdu = pdu->inner_pdu();
    if (pdu->pdu_type() == Tins::PDU::ARP) {
        pkt_info->top_pdu_type = pkt_info_t::pdu_type_t::ARP;
        pkt_info->pdu_hash.insert(pkt_info_t::ARP, pdu);
        pkt_info->pdu_list.append(QPair<enum pkt_info_t::pdu_type_t, Tins::PDU*>(pkt_info_t::ARP, pdu));

    } else if (pdu->pdu_type() == Tins::PDU::IP) {
        if (pdu->inner_pdu() == nullptr)
            goto proc_failed;
        pkt_info->pdu_hash.insert(pkt_info_t::IP, pdu);
        pkt_info->pdu_list.append(QPair<enum pkt_info_t::pdu_type_t, Tins::PDU*>(pkt_info_t::IP, pdu));
        pdu = pdu->inner_pdu();

        if (pdu->pdu_type() == Tins::PDU::TCP) {
            pkt_info->pdu_hash.insert(pkt_info_t::TCP, pdu);
            pkt_info->pdu_list.append(QPair<enum pkt_info_t::pdu_type_t, Tins::PDU*>(pkt_info_t::TCP, pdu));
        } else if (pdu->pdu_type() == Tins::PDU::UDP) {
            pkt_info->pdu_hash.insert(pkt_info_t::UDP, pdu);
            pkt_info->pdu_list.append(QPair<enum pkt_info_t::pdu_type_t, Tins::PDU*>(pkt_info_t::UDP, pdu));
        } else if (pdu->pdu_type() == Tins::PDU::ICMP) {
            pkt_info->top_pdu_type = pkt_info_t::pdu_type_t::ICMP;
            pkt_info->pdu_hash.insert(pkt_info_t::ICMP, pdu);
            pkt_info->pdu_list.append(QPair<enum pkt_info_t::pdu_type_t, Tins::PDU*>(pkt_info_t::ICMP, pdu));
        } else {
            goto proc_failed;
        }
        if (pdu->pdu_type() == Tins::PDU::TCP || pdu->pdu_type() == Tins::PDU::UDP) {
            if (!__set_app_layer_protocol(pkt_info)) {
                qDebug() << __LINE__;
                goto proc_failed;
            }
        }
    } else {
        goto proc_failed;
    }

    //fullfill other fileds
    static const char *prot;
    pkt_info->timestamp = pkt->timestamp();
    strncpy(pkt_info->overview.timestampstr, __timestamp_to_str(pkt_info->timestamp), 63);
    pkt_info->overview.timestampstr[63] = '\0';
    pkt_info->overview.size = raw_pdu->size();
    if (pkt_info->top_pdu_type == pkt_info_t::pdu_type_t::ARP) {
        strncpy(pkt_info->overview.src,
                static_cast<Tins::EthernetII*>(pkt_info->pdu_hash.value(pkt_info_t::EthernetII))->src_addr().to_string().data(),
                31);
        strncpy(pkt_info->overview.dst,
                static_cast<Tins::EthernetII*>(pkt_info->pdu_hash.value(pkt_info_t::EthernetII))->dst_addr().to_string().data(),
                31);
        prot = "ARP";

    } else {
        if (pkt_info->pdu_hash.contains(pkt_info_t::TCP)) {
            std::sprintf(pkt_info->overview.src,
                         "%s:%d",
                         static_cast<Tins::IP*>(pkt_info->pdu_hash.value(pkt_info_t::IP))->src_addr().to_string().data(),
                         static_cast<Tins::TCP*>(pkt_info->pdu_hash.value(pkt_info_t::TCP))->sport());
            std::sprintf(pkt_info->overview.dst,
                         "%s:%d",
                         static_cast<Tins::IP*>(pkt_info->pdu_hash.value(pkt_info_t::IP))->dst_addr().to_string().data(),
                         static_cast<Tins::TCP*>(pkt_info->pdu_hash.value(pkt_info_t::TCP))->dport());
        } else if (pkt_info->pdu_hash.contains(pkt_info_t::UDP)) {
            std::sprintf(pkt_info->overview.src,
                         "%s:%d",
                         static_cast<Tins::IP*>(pkt_info->pdu_hash.value(pkt_info_t::IP))->src_addr().to_string().data(),
                         static_cast<Tins::UDP*>(pkt_info->pdu_hash.value(pkt_info_t::UDP))->sport());
            std::sprintf(pkt_info->overview.dst,
                         "%s:%d",
                         static_cast<Tins::IP*>(pkt_info->pdu_hash.value(pkt_info_t::IP))->dst_addr().to_string().data(),
                         static_cast<Tins::UDP*>(pkt_info->pdu_hash.value(pkt_info_t::UDP))->dport());
        } else {
            strcpy(pkt_info->overview.src,
                   static_cast<Tins::IP*>(pkt_info->pdu_hash.value(pkt_info_t::IP))->src_addr().to_string().data());
            strcpy(pkt_info->overview.dst,
                         static_cast<Tins::IP*>(pkt_info->pdu_hash.value(pkt_info_t::IP))->dst_addr().to_string().data());
        }
        switch (pkt_info->top_pdu_type) {
            case pkt_info_t::pdu_type_t::FTP:
                prot = "FTP";
                break;
            case pkt_info_t::pdu_type_t::DNS:
                prot = "DNS";
                break;
            case pkt_info_t::pdu_type_t::HTTP:
                prot = "HTTP";
                break;
            case pkt_info_t::pdu_type_t::HTTPS:
                prot = "HTTPS";
                break;
            case pkt_info_t::pdu_type_t::IMAP:
                prot = "IMAP";
                break;
            case pkt_info_t::pdu_type_t::POP3:
                prot = "POP3";
                break;
            case pkt_info_t::pdu_type_t::SMTP:
                prot = "SMTP";
                break;
            case pkt_info_t::pdu_type_t::SNMP:
                prot = "SNMP";
                break;
            case pkt_info_t::pdu_type_t::TELNET:
                prot = "TELNET";
                break;
            case pkt_info_t::pdu_type_t::ICMP:
                prot = "ICMP";
                break;
            case pkt_info_t::pdu_type_t::UNKNOWN_TCP:
                prot = "TCP";
                break;
            case pkt_info_t::pdu_type_t::UNKNOWN_UDP:
                prot = "UDP";
                break;
            default:
                qDebug() << __LINE__;

                goto proc_failed;
        }
    }
    strcpy(pkt_info->overview.protocol, prot);

    for (QPair<enum pkt_info_t::pdu_type_t, Tins::PDU *> pair : pkt_info->pdu_list) {
        __run_processors(pair);
    }

    emit new_pkt_info(pkt_info);

    return;
proc_failed:
    fprintf(stderr, "proc failed!\n");
    delete raw_pdu;
    if (pkt_info != nullptr) {
        delete pkt_info->pdus.eii_pdu;
        delete pkt_info;
    }
    return;
}

bool pkt_processor::__set_app_layer_protocol(pkt_info_t *pi)
{
    static uint16_t sp, dp;
    static Tins::TCP *tcp_pdu;
    static Tins::UDP *udp_pdu;
    static Tins::IP *ip_pdu;
    static bool is_tcp, is_udp;
    is_tcp = is_udp = false;
    if (!pi->pdu_hash.contains(pkt_info_t::IP)) {
        qDebug() << __LINE__;

        return false;
    }
    if (pi->pdu_hash.contains(pkt_info_t::TCP)) {
        tcp_pdu = static_cast<Tins::TCP *>(pi->pdu_hash.value(pkt_info_t::TCP));
        sp = tcp_pdu->sport();
        dp = tcp_pdu->dport();
        is_tcp = true;
    } else if (pi->pdu_hash.contains(pkt_info_t::UDP)) {
        udp_pdu = static_cast<Tins::UDP *>(pi->pdu_hash.value(pkt_info_t::UDP));
        sp = udp_pdu->sport();
        dp = udp_pdu->dport();
        is_udp = true;
    } else {
        qDebug() << __LINE__;

        return false;
    }
    if (is_tcp && (sp == FTP_PORT || dp == FTP_PORT)) {
        pi->top_pdu_type = pkt_info_t::pdu_type_t::FTP;
    } else if (is_tcp && (sp == HTTP_PORT || dp == HTTP_PORT)) {
        pi->top_pdu_type = pkt_info_t::pdu_type_t::HTTP;
    } else if (is_tcp && (sp == HTTPS_PORT || dp == HTTPS_PORT)) {
        pi->top_pdu_type = pkt_info_t::pdu_type_t::HTTPS;
    } else if (is_udp && (sp == DNS_PORT || dp == DNS_PORT)) {
        pi->top_pdu_type = pkt_info_t::pdu_type_t::DNS;
    } else if (is_tcp && (sp == SMTP_PORT || dp == SMTP_PORT)) {
        pi->top_pdu_type = pkt_info_t::pdu_type_t::SMTP;
    } else if (is_tcp && (sp == POP3_PORT || dp == POP3_PORT)) {
        pi->top_pdu_type = pkt_info_t::pdu_type_t::POP3;
    } else if (is_udp && (sp == SNMP_PORT || dp == SNMP_PORT)) {
        pi->top_pdu_type = pkt_info_t::pdu_type_t::SNMP;
    } else if (is_tcp && (sp == TELNET_PORT || dp == TELNET_PORT)) {
        pi->top_pdu_type = pkt_info_t::pdu_type_t::TELNET;
    } else if (is_tcp && (sp == IMAP_PORT || dp == IMAP_PORT)) {
        pi->top_pdu_type = pkt_info_t::pdu_type_t::IMAP;
    } else if (is_tcp){
        pi->top_pdu_type = pkt_info_t::pdu_type_t::UNKNOWN_TCP;
    } else if (is_udp) {
        pi->top_pdu_type = pkt_info_t::pdu_type_t::UNKNOWN_UDP;
    } else {
        qDebug() << __LINE__;

        return false;
    }
    return true;
}

const char *pkt_processor::__timestamp_to_str(Tins::Timestamp &timestamp)
{
    time_t sec_tv = timestamp.seconds();
    struct tm *localtm = std::localtime(&sec_tv);
    static char tmpstr[64];
    memset(tmpstr, 0x00, sizeof(tmpstr));
    std::strftime(tmpstr, 31, "%F %T", localtm);
    std::snprintf(tmpstr + strlen(tmpstr), 31, " %lu ms %lu us",
                  (unsigned long)timestamp.microseconds() / 1000,
                  (unsigned long)timestamp.microseconds() % 1000);
    return tmpstr;
}

void pkt_processor::__run_processors(QPair<enum pkt_info_t::pdu_type_t, Tins::PDU *> &pair)
{

}

