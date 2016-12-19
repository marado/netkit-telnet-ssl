#include "ring.h"
#include "glue.h"
#include "externs.h"
#include "proto.h"

int netflush_h(void) {
  return netflush();
}

void printsub_h(int direction, unsigned char *pointer, int length) {
  printsub(direction, pointer, length);
}

