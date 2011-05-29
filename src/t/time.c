/* Implementation for simple time-testing */

// Includes
#include "time.h"

// Implementation
unsigned long long timeval_diff(struct timeval *start,
                                struct timeval * end) {

  // Start and end times in usec (nano)
  unsigned long long start_val = 0;
  unsigned long long stop_val = 0;

  // Converts the start time
  start_val = start->tv_sec  * 1000000    +
              start->tv_usec;

  // Converts the end time
  stop_val = end->tv_sec  * 1000000    +
             end->tv_usec;

  // Returns the difference between the two times
  return stop_val - start_val;
}
