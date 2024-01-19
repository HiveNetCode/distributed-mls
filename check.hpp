/**
 * @file check.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Simple error checking utility
 */

#ifndef __CHECK_HPP__
#define __CHECK_HPP__

#include <cstdio>
#include <cstdlib>

static void sys_error(const char * msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

#define STRINGIFY(x) #x
#define STR(x) STRINGIFY(x)

#define PCHECK(ret)                                                            \
do {                                                                           \
    if ((ret) == -1) { sys_error(__FILE__ ":" STR(__LINE__) " " #ret); }       \
} while (0)

#define CHECK(ret)                                                             \
do {                                                                           \
    if (!(ret)) { sys_error(__FILE__ ":" STR(__LINE__) " " #ret); }            \
} while (0)

#define ERROR(str)                                                             \
do {                                                                           \
    fprintf(stderr, __FILE__ ":" STR(__LINE__) " " str); exit(EXIT_FAILURE);   \
} while (0)

#endif
