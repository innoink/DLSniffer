#include "protocol_sniffers.h"

#include <cstdio>
#include <QRegExp>
#include <QStringList>
#include <QDebug>
#include <QtGlobal>


sniffer_result protocol_sniffers::sresult;

void protocol_sniffers::http_sniffer(const Tins::PDU *http_pdu)
{
    const Tins::RawPDU *r_http_pdu;
    r_http_pdu = static_cast<const Tins::RawPDU*>(http_pdu);

    QString http_str(reinterpret_cast<const char *>(r_http_pdu->payload().data()));

    QString prot("HTTP");
    QString site;
    QString empty;
    int pos = 0;
    QRegExp siterx("(Referer: )([^\\r]*)(\\r\\n)");
    siterx.setCaseSensitivity(Qt::CaseInsensitive);
    pos = siterx.indexIn(http_str, pos);
    if (pos != -1) {
        site = siterx.cap(2);
    }
    QRegExp namerx("(username|userid|uid|login|user)(\\w{0,})(=)(\\w{1,32})(\\W)");
    QRegExp passrx("(password|pass|passwd)(\\w{0,})(=)(\\w{1,32})(\\W)");
    namerx.setCaseSensitivity(Qt::CaseInsensitive);
    passrx.setCaseSensitivity(Qt::CaseInsensitive);
    QStringList namelist;
    QStringList passlist;
    pos = 0;
    while ((pos = namerx.indexIn(http_str, pos)) != -1) {
        namelist << namerx.cap(4);
        pos += namerx.matchedLength();
    }
    pos = 0;
    while ((pos = passrx.indexIn(http_str, pos)) != -1) {
        passlist << passrx.cap(4);
        pos += passrx.matchedLength();
    }
    for (int i = 0; i < qMax(namelist.length(), passlist.length()); i++) {
        emit sresult.new_sniffer_result(
                                        prot,
                                        site,
                                        i >= namelist.length() ? empty : namelist.at(i),
                                        i >= passlist.length() ? empty : passlist.at(i)
                                        );
    }


}
