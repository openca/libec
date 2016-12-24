/* Simple Time Testing function from libpki */

// Standard Includes
#include <string.h>

#include <time.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/times.h>

#include <unistd.h>
#include <sys/types.h>

// Function Prototype
unsigned long long timeval_diff(struct timeval *start, 
		                struct timeval * end);
