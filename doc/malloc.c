#include <stdlib.h>
#include <stdio.h>


void main(void) {
  char *p = (char *)malloc(10*(sizeof(char)));
  p[0] = 'A';
  if (p) {
    p[1] = 'B';
    free(p);
  } else {
    p[1] = 'C';
  }
  p[2] = 0;
  p[0] = 0;
  printf("%s", p);
}

