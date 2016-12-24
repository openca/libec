#include "main.h"

// DEBUG MACRO - TO BE REMOVED
//
// a ....: FILE * where to write to (e.g., stderr)
// v ....: Name/Identifier for the data to be debugged
// b ....: Pointer to the Unsigned Char buffer
// c ....: Size (bytes) of the buffer to dump
#define DEBUG_UNSIGNED(a,v,b,c)                              \
    {   size_t _idx;                                         \
        fprintf(a, "[%s::%d::%s()] %s = { \n", __FILE__, __LINE__, __PRETTY_FUNCTION__, v); \
        fprintf(a, "[%s::%d::%s()]     ", __FILE__, __LINE__,  __PRETTY_FUNCTION__); \
        unsigned char * k = (unsigned char *)b;              \
        for (_idx = 0; _idx < (size_t) c; _idx++) {          \
           unsigned char cHR;                                \
           cHR = (unsigned char) k[_idx];                    \
           fprintf(a, "0x%2.2x", cHR);                       \
           if (_idx < (size_t) c) fprintf(a, " ");           \
           else fprintf(a, "\n");                            \
           if (_idx > 0 && _idx % 8 == 0) \
         fprintf(a, "\n[%s::%d::%s()]     ", __FILE__, __LINE__,  __PRETTY_FUNCTION__);  \
        }                                                    \
        fprintf(a, "[%s::%d::%s()]   }\n", __FILE__, __LINE__,  __PRETTY_FUNCTION__); \
    }

