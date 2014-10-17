#include "pkt_processor.h"
#include <ctime>
#include <cstdio>
#include <cstring>
#include "sniffer/dlsniffer_defs.h"

#include <QDebug>

pkt_processor::pkt_processor(queue_t *pkt_queue, QReadWriteLock *stop_rwlock) :
    pkt_worker(pkt_queue, stop_rwlock), pkt_cnt(0)
{
    port_protocol_map.insert(HTTP_PORT, {pkt_info_t::HTTP, pkt_info_t::TCP, "HTTP"});
    port_protocol_map.insert(HTTPS_PORT, {pkt_info_t::HTTPS, pkt_info_t::TCP, "HTTPS"});
    port_protocol_map.insert(FTP_PORT, {pkt_info_t::FTP, pkt_info_t::TCP, "FTP"});
    port_protocol_map.insert(DNS_PORT, {pkt_info_t::DNS, pkt_info_t::UDP, "DNS"});
    port_protocol_map.insert(SMTP_PORT, {pkt_info_t::SMTP, pkt_info_t::TCP, "SMTP"});
    port_protocol_map.insert(POP3_PORT, {pkt_info_t::POP3, pkt_info_t::TCP, "POP3"});
    port_protocol_map.insert(SNMP_PORT, {pkt_info_t::SNMP, pkt_info_t::UDP, "SNMP"});
    port_protocol_map.insert(IMAP_PORT, {pkt_info_t::IMAP, pkt_info_t::TCP, "IMAP"});
    port_protocol_map.insert(TELNET_PORT, {pkt_info_t::TELNET, pkt_info_t::TCP, "TELNET"});

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
    pkt_info->pdu_hash.insert(pkt_info_t::EthernetII, eii_pdu);
    pkt_info->pdu_list.append(QPair<enum pkt_info_t::pdu_type_t, Tins::PDU*>(pkt_info_t::EthernetII, eii_pdu));
    //check valid pdu
    static Tins::PDU *pdu;
    pdu = eii_pdu;
    if (pdu->inner_pdu() == nullptr)
        goto proc_failed;
    pdu = pdu->inner_pdu();
    if (pdu->pdu_type() == Tins::PDU::ARP) {
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
            pkt_info->pdu_hash.insert(pkt_info_t::ICMP, pdu);
            pkt_info->pdu_list.append(QPair<enum pkt_info_t::pdu_type_t, Tins::PDU*>(pkt_info_t::ICMP, pdu));
        } else {
            goto proc_failed;
        }
    } else {
        goto proc_failed;
    }
    if (!__set_top_layer_protocol(pkt_info)) {
        qDebug() << __LINE__;
        goto proc_failed;
    }

    //fullfill other fileds
    pkt_info->timestamp = pkt->timestamp();
    strncpy(pkt_info->overview.timestampstr, __timestamp_to_str(pkt_info->timestamp), 63);
    pkt_info->overview.timestampstr[63] = '\0';
    pkt_info->overview.size = raw_pdu->size();
    if (pkt_info->pdu_hash.contains(pkt_info_t::ARP)) {
        strncpy(pkt_info->overview.src,
                static_cast<Tins::EthernetII*>(pkt_info->pdu_hash.value(pkt_info_t::EthernetII))->src_addr().to_string().data(),
                31);
        strncpy(pkt_info->overview.dst,
                static_cast<Tins::EthernetII*>(pkt_info->pdu_hash.value(pkt_info_t::EthernetII))->dst_addr().to_string().data(),
                31);

    } else {
        char s_sp[8] = {0}, s_dp[8] = {0};

        if (pkt_info->pdu_hash.contains(pkt_info_t::TCP)) {
            std::sprintf(s_sp,
                         ":%d",
                         static_cast<Tins::TCP*>(pkt_info->pdu_hash.value(pkt_info_t::TCP))->sport());
            std::sprintf(s_dp,
                         ":%d",
                         static_cast<Tins::TCP*>(pkt_info->pdu_hash.value(pkt_info_t::TCP))->dport());
        } else if (pkt_info->pdu_hash.contains(pkt_info_t::UDP)) {
            std::sprintf(s_sp,
                         ":%d",
                         static_cast<Tins::UDP*>(pkt_info->pdu_hash.value(pkt_info_t::UDP))->sport());
            std::sprintf(s_dp,
                         ":%d",
                         static_cast<Tins::UDP*>(pkt_info->pdu_hash.value(pkt_info_t::UDP))->dport());
        }
        std::sprintf(pkt_info->overview.src,
                     "%s%s",
                     static_cast<Tins::IP*>(pkt_info->pdu_hash.value(pkt_info_t::IP))->src_addr().to_string().data(),
                     s_sp);
        std::sprintf(pkt_info->overview.dst,
                     "%s%s",
                     static_cast<Tins::IP*>(pkt_info->pdu_hash.value(pkt_info_t::IP))->dst_addr().to_string().data(),
                     s_dp);
    }

    for (QPair<enum pkt_info_t::pdu_type_t, Tins::PDU *> pair : pkt_info->pdu_list) {
//        qDebug() << pair.first;
        __run_processors(pair);
    }

    emit new_pkt_info(pkt_info);

    return;
proc_failed:
    fprintf(stderr, "proc failed!\n");
    delete raw_pdu;
    if (pkt_info != nullptr) {
        delete pkt_info;
    }
    return;
}

bool pkt_processor::__set_top_layer_protocol(pkt_info_t *pi)
{
    static uint16_t sp = -1, dp = -1;
    static Tins::TCP *tcp_pdu;
    static Tins::UDP *udp_pdu;
    if (pi->pdu_hash.contains(pkt_info_t::ARP)) {
            pi->top_pdu_type = pkt_info_t::ARP;
            strcpy(pi->overview.protocol, "ARP");
            return true;
    }
    if (pi->pdu_hash.contains(pkt_info_t::ICMP)) {
            pi->top_pdu_type = pkt_info_t::ICMP;
            strcpy(pi->overview.protocol, "ICMP");
            return true;
    }
    if (pi->pdu_hash.contains(pkt_info_t::TCP)) {
        tcp_pdu = static_cast<Tins::TCP *>(pi->pdu_hash.value(pkt_info_t::TCP));
        sp = tcp_pdu->sport();
        dp = tcp_pdu->dport();
    } else if (pi->pdu_hash.contains(pkt_info_t::UDP)) {
        udp_pdu = static_cast<Tins::UDP *>(pi->pdu_hash.value(pkt_info_t::UDP));
        sp = udp_pdu->sport();
        dp = udp_pdu->dport();
    }
    int known_port = -1;
    if (port_protocol_map.contains(sp)) known_port = sp;
    else if (port_protocol_map.contains(dp)) known_port = dp;
    if (known_port != -1) {
        if (pi->pdu_hash.contains(port_protocol_map.value(known_port).trans_type)) {
            if (pi->pdu_hash.value(port_protocol_map.value(known_port).trans_type)->inner_pdu() != nullptr &&
                pi->pdu_hash.value(port_protocol_map.value(known_port).trans_type)->inner_pdu()->size() != 0) {

                pi->top_pdu_type = port_protocol_map.value(known_port).app_type;
                strcpy(pi->overview.protocol, port_protocol_map.value(known_port).str);
                pi->pdu_hash.insert(port_protocol_map.value(known_port).app_type,
                                    pi->pdu_hash.value(port_protocol_map.value(known_port).trans_type)->inner_pdu());
                pi->pdu_list.append(QPair<enum pkt_info_t::pdu_type_t, Tins::PDU*>(
                                        port_protocol_map.value(known_port).app_type,
                                        pi->pdu_hash.value(port_protocol_map.value(known_port).trans_type)->inner_pdu()));
            }
        }
    }
    if (pi->pdu_hash.contains(pkt_info_t::TCP) &&
        (known_port == -1 || pi->pdu_hash.value(pkt_info_t::TCP)->inner_pdu() == nullptr ||
         pi->pdu_hash.value(pkt_info_t::TCP)->inner_pdu()->size() == 0)) {
        pi->top_pdu_type = pkt_info_t::pdu_type_t::UNKNOWN_TCP;
        strcpy(pi->overview.protocol, "TCP");
    }
    if (pi->pdu_hash.contains(pkt_info_t::UDP) &&
        (known_port == -1 || pi->pdu_hash.value(pkt_info_t::UDP)->inner_pdu() == nullptr ||
         pi->pdu_hash.value(pkt_info_t::UDP)->inner_pdu()->size() == 0)) {
        pi->top_pdu_type = pkt_info_t::pdu_type_t::UNKNOWN_UDP;
        strcpy(pi->overview.protocol, "UDP");
    }
    if (known_port == -1 && !pi->pdu_hash.contains(pkt_info_t::UDP) && !pi->pdu_hash.contains(pkt_info_t::TCP)) {
//        qDebug() << __LINE__;
        return false;
    }
    if (pi->pdu_hash.contains(pkt_info_t::TCP)) {
        if (tcp_pdu->get_flag(Tins::TCP::SYN) == 1 && tcp_pdu->get_flag(Tins::TCP::ACK) == 0) {
            pi->top_pdu_type = pkt_info_t::pdu_type_t::TCP;
            strcpy(pi->overview.protocol, "TCP_SYN");
        }
        if (tcp_pdu->get_flag(Tins::TCP::SYN) == 0 && tcp_pdu->get_flag(Tins::TCP::ACK) == 1) {
            if (tcp_pdu->inner_pdu() == nullptr || tcp_pdu->inner_pdu()->size() == 0) {
                pi->top_pdu_type = pkt_info_t::pdu_type_t::TCP;
                strcpy(pi->overview.protocol, "TCP_ACK");
            }
        }
        if (tcp_pdu->get_flag(Tins::TCP::SYN) == 1 && tcp_pdu->get_flag(Tins::TCP::ACK) == 1) {
            pi->top_pdu_type = pkt_info_t::pdu_type_t::TCP;
            strcpy(pi->overview.protocol, "TCP_SYN_ACK");
        }
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

void pkt_processor::add_pdu_processor(pkt_info_t::pdu_type_t ptype, pdu_processor_func_t processor)
{
    this->pdu_processors.insert(ptype, processor);
}

void pkt_processor::remove_pdu_processor(pkt_info_t::pdu_type_t ptype, pdu_processor_func_t processor)
{
    this->pdu_processors.remove(ptype, processor);
}

void pkt_processor::clear_pdu_processors()
{
    this->pdu_processors.clear();
}

void pkt_processor::__run_processors(QPair<enum pkt_info_t::pdu_type_t, Tins::PDU *> &pair)
{
    for (pdu_processor_func_t i : pdu_processors.values(pair.first)) {
        i(pair.second);
    }
}

