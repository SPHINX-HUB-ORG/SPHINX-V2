//
// Created by roee on 1/16/19.
//

#ifdef __x86_64__
#ifndef __APPLE__
#include "../../include/comm/utils.h"

#include <sys/time.h>

void
itimeofday(long *sec, long *usec) {
  struct timeval time;
  gettimeofday(&time, NULL);
  if (sec) *sec = time.tv_sec;
  if (usec) *usec = time.tv_usec;
}

IUINT64 iclock64(void) {
  long s, u;
  IUINT64 value;
  itimeofday(&s, &u);
  value = ((IUINT64) s) * 1000 + (u / 1000);

  return value;
}

IUINT32 iclock() {
  return (IUINT32) (iclock64() & 0xfffffffful);
}

#endif
#endif
