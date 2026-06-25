#include "test.h"
#include "varint_test.c"
#include "header_test.c"
#include "pnum_test.c"

int main(void)
{
    test_varint();
    test_header();
    test_pnum();
    return TEST_REPORT();
}
