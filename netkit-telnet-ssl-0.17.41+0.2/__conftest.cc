#include <stdio.h>
int main() {
    void *x = (void *)snprintf;
    printf("%lx", (long)x);
    return 0;
}

