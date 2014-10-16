#include <stdexcept>
#include "sniffer/protocol_sniffers.h"
#include "sniffer_manager.h"

sniffer_manager::sniffer_manager(QObject *parent) :
    QObject(parent)
{
    sniffer = nullptr;
    pkt_queue = queue_create();
    pc_stoprwlock = new QReadWriteLock;
    pp_stoprwlock = new QReadWriteLock;

    pc_thrd = new pkt_capture(pkt_queue, pc_stoprwlock);
    pp_thrd = new pkt_processor(pkt_queue, pp_stoprwlock);

    pp_thrd->add_pdu_processor(pkt_info_t::HTTP, protocol_sniffers::http_sniffer);
}
sniffer_manager::~sniffer_manager()
{
    stop_capture();
    release_sniffer();
    delete pc_thrd;
    delete pp_thrd;
    delete pc_stoprwlock;
    delete pp_stoprwlock;
    queue_destroy(pkt_queue);
    destroy_pkt_info_list();

}

void sniffer_manager::destroy_pkt_info_list()
{
    for (auto i : pkt_info_list)
        delete i;
    pkt_info_list.clear();
}

void sniffer_manager::set_nif(Tins::NetworkInterface nif)
{
    this->nif = nif;
}

Tins::NetworkInterface sniffer_manager::get_nif()
{
    return nif;
}

void sniffer_manager::set_filter(const char *flt)
{
    sconf.set_filter(flt);
}

void sniffer_manager::set_promisc(bool b)
{
    this->sconf.set_promisc_mode(b);
}

bool sniffer_manager::init_sniffer()
{
    try {
        sniffer = new Tins::Sniffer(nif.name(), sconf);
    } catch (std::runtime_error) {
        sniffer = nullptr;
        return false;
    }
    pc_thrd->set_sniffer(sniffer);
    return true;
}

void sniffer_manager::release_sniffer()
{
    delete this->sniffer;
    this->sniffer = nullptr;
}

void sniffer_manager::start_capture()
{
    pp_thrd->start_work();
    pc_thrd->start_work();
}

//should have a callback
void sniffer_manager::stop_capture()
{
    pc_thrd->stop_work();
    pp_thrd->stop_work();
}
