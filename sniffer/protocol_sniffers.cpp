#include "protocol_sniffers.h"

#include <cstdio>

QList<protocol_sniffers::http_password_t> protocol_sniffers::http_param;

static const char* uname_fileds[5] = {
  "login",
  "username",
  "loginname",
  "user",
  "id"
};

void protocol_sniffers::http_sniffer(const Tins::PDU *http_pdu)
{
    protocol_sniffers::http_password_t http_password;
    const Tins::RawPDU *r_http_pdu;
    QList<protocol_sniffers::http_password_t> *passwords_list;
    passwords_list = &protocol_sniffers::http_param;
    r_http_pdu = static_cast<const Tins::RawPDU*>(http_pdu);

    QString http_str(reinterpret_cast<const char *>(r_http_pdu->payload().data()));
    for (auto u : uname_fileds) {
        if (http_str.contains(u, Qt::CaseInsensitive)) {
            int i;
            for (i = http_str.indexOf(u, 0, Qt::CaseInsensitive); i < http_str.size() && (http_str.at(i).isLetterOrNumber() || http_str.at(i) == '_'); i++);
            i++;
            if (i >= http_str.size())
                continue;
            for (; i < http_str.size() && (http_str.at(i).isLetterOrNumber() || http_str.at(i) == '_'); i++) {
                fprintf(stderr, "%c", http_str.at(i).toLatin1());
            }
            fprintf(stderr, "\n");
        }
    }

}
