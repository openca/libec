/* codes.h */

#ifndef LIBEC_CODES_H
#define LIBEC_CODES_H

#ifndef LIBEC_COMPAT_H
#include <libeasycrypto/compat.h>
#endif

BEGIN_C_DECLS

typedef enum {
    LIBEC_OK                            = 0
    // Generic Success
  , LIBEC_ERR                           = 1
    // Generic Error
} LIBEC_CODE;

END_C_DECLS

#endif // LIBEC_CODES_H


