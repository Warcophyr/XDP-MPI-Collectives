#pragma once
#include <time.h>
#include <sys/time.h>

inline double cp_Wtime() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + 1.0e-6 * tv.tv_usec;
}

inline double get_time(double time) { return (cp_Wtime()) - time; }