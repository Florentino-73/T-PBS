#ifndef _TEST_TIMING_H
#define _TEST_TIMING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>

# define timespec_add(a, b, result)                   \
  do {                                                \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;     \
    (result)->tv_nsec = (a)->tv_nsec + (b)->tv_nsec;  \
    if ((result)->tv_nsec >= 1000000000)              \
    {                                                 \
     ++(result)->tv_sec;                              \
     (result)->tv_nsec -= 1000000000;                 \
    }                                                 \
  } while (0)

# define timespec_sub(a, b, result)                   \
  do {                                                \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;     \
    (result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;  \
    if ((result)->tv_nsec < 0) {                      \
      --(result)->tv_sec;                             \
      (result)->tv_nsec += 1000000000;                \
    }                                                 \
  } while (0)

#define BENCHMARK_START(X)                            \
  struct timespec start_##X, end_##X, X;              \
  clock_gettime(CLOCK_MONOTONIC, &start_##X)          \

#define BENCHMARK_STOP(X)                             \
  do {                                                \
    clock_gettime(CLOCK_MONOTONIC, &end_##X);         \
    timespec_sub(&end_##X, &start_##X, &X);           \
  } while(0)

// extern struct timespec sum_ias_ver_quote;
// extern struct timespec sum_ias_gen_quote;

#ifdef __cplusplus
}
#endif

#endif