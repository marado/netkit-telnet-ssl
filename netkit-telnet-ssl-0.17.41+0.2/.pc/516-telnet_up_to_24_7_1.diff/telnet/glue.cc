#include "ring.h"
#include "glue.h"

extern ringbuf netoring;

extern "C" int netflush(void) {
  return netflush_h();
}

extern "C" void printsub(int direction, unsigned char *pointer, int length) {
  printsub_h(direction, pointer, length);
}

extern "C" void writenet(const char *str, int len) {
  netoring.write(str, len);
}

extern "C" int telnet_spin() {
  return(-1);
}
