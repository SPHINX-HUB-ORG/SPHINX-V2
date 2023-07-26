//
// Created by roee on 1/16/19.
//

#ifndef CONNECTIONLESS_PROTOCOL_UTILS_H
#define CONNECTIONLESS_PROTOCOL_UTILS_H

#include <log4cpp/Category.hh>

#include <KCP/ikcp.h>

#define KCP_CHECK(v, cat) { \
  if ((v) < 0) { \
    log4cpp::Category::getInstance(cat).errorStream() << "kcp error (code: " << (v) << "), aborting (file: " \
    << __FILE__ << ", line: " << __LINE__ << ")"; \
    abort();  \
  } \
}

void itimeofday(long *sec, long *usec);
IUINT64 iclock64(void);
IUINT32 iclock();

#endif //CONNECTIONLESS_PROTOCOL_UTILS_H
