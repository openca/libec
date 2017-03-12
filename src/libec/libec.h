// crypto.h - private include

#ifndef LIBEC_H
#define LIBEC_H

// Standard Includes
#include <stdio.h>
#include <string.h>

#include <time.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/times.h>

#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>

#ifndef _STDINT_H
#include <stdint.h>
#endif

// OpenSSL Includes
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/opensslconf.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

// Library Includes
#ifndef LIBEC_COMPAT_H
#include <libec/compat.h>
#endif

BEGIN_C_DECLS

// OpenSSL Compatibility Defines
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
# define EVP_MD_CTX_new EVP_MD_CTX_create
# define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

// ===========
// Definitions
// ===========

typedef ASN1_OCTET_STRING HMAC_VALUE;

// DIGEST algorithms
typedef enum {
  // Symmetric Algor
  LIBEC_DIGEST_ALG_UNKNOWN  = 0x0,
  LIBEC_DIGEST_ALG_SHA256    = 0x1,
  LIBEC_DIGEST_ALG_SHA384    = 0x2,
  LIBEC_DIGEST_ALG_SHA512    = 0x3
} LIBEC_DIGEST_ALG;

// Default Diget Algorithm
#define LIBEC_DIGEST_ALG_ANY     LIBEC_DIGEST_ALG_UNKNOWN
#define LIBEC_DIGEST_ALG_DEFAULT LIBEC_DIGEST_ALG_SHA256

// SYMMETRIC and ASYMMETRIC schemes
typedef enum {
  // Asymmetric Algorithms
  LIBEC_ALGOR_UNKNOWN      = 0x0,
  LIBEC_ALGOR_HMAC        = 0x1 << 4,
  LIBEC_ALGOR_RSA          = 0x3 << 4,
  LIBEC_ALGOR_ECDSA        = 0x4 << 4
} LIBEC_ALGOR;

// Default Crypto Algor
#define LIBEC_ALGOT_ANY     LIBEC_ALGOR_UNKNOWN
#define LIBEC_ALGOR_DEFAULT LIBEC_ALGOR_ECDSA

// Masks for Algorithm and Digest identifiers extraction
#define LIBEC_ALGOR_MASK        0xF0
#define LIBEC_DIGEST_ALG_MASK   0x0F

// ENCRYPTION modes
typedef enum {
  LIBEC_ENC_MODE_UNKNOWN  = 0x0,
  LIBEC_ENC_MODE_CBC      = 0x1,
  LIBEC_ENC_MODE_GCM      = 0x2
} LIBEC_ENC_MODE;

// Default Encryption Mode
#define LIBEC_ENC_MODE_ANY     LIBEC_ENC_MODE_UNKNOWN
#define LIBEC_ENC_MODE_DEFAULT LIBEC_ENC_MODE_GCM

// ENCRYPTION algorithms
typedef enum {
  LIBEC_ENC_ALG_UNKNOWN    = 0x0,
  LIBEC_ENC_ALG_AES_128    = 0x1 << 4,
  LIBEC_ENC_ALG_AES_192    = 0x2 << 4,
  LIBEC_ENC_ALG_AES_256    = 0x3 << 4,
  // Asymmetric
  LIBEC_ENC_ALG_RSA       = 0x4 << 4,
  LIBEC_ENC_ALG_ECDSA     = 0x5 << 5
} LIBEC_ENC_ALG;

// ANY Encryption Algorithm
#define LIBEC_ENC_ALG_ANY       LIBEC_ENC_ALG_UNKNOWN
#define LIBEC_ENC_ALG_DEFAULT   LIBEC_ENC_ALG_AES_128

// Masks for Algorithm and Digest identifiers extraction
#define LIBEC_ENC_ALG_MASK    0xF0
#define LIBEC_ENC_MODE_MASK   0x0F

// TAG length for AEAD ciphers
#define LIBEC_AEAD_TAG_LENGTH   16
#define LIBEC_ENC_ALG_tag_size(alg) \
  ((alg & LIBEC_ENC_MODE_MASK) == LIBEC_ENC_MODE_GCM ? LIBEC_AEAD_TAG_LENGTH : 0)

// EC Supported Curves
typedef enum {
  LIBEC_EC_CURVE_UNKNOWN   = 0,
  LIBEC_EC_CURVE_GOOD      = NID_secp256k1,
  LIBEC_EC_CURVE_BETTER    = NID_sect409k1,
  LIBEC_EC_CURVE_BEST     = NID_sect571k1
} LIBEC_EC_CURVE;

// Defaults for EC CURVE
#define LIBEC_EC_CURVE_ANY        LIBEC_EC_CURVE_UNKNOWN
#define LIBEC_EC_CURVE_DEFAULT    LIBEC_EC_CURVE_GOOD

// RSA Supported sizes
typedef enum {
  LIBEC_RSA_SIZE_UNKNOWN  = 0,
  LIBEC_RSA_SIZE_GOOD      = 2048,
  LIBEC_RSA_SIZE_BETTER    = 3072,
  LIBEC_RSA_SIZE_BEST      = 4096
} LIBEC_RSA_SIZE;

// RSA Defaults
#define LIBEC_RSA_SIZE_ANY        LIBEC_RSA_SIZE_UNKNOWN
#define LIBEC_RSA_SIZE_DEFAULT    LIBEC_RSA_SIZE_GOOD

// AES Supported Sizes
typedef enum {
  LIBEC_AES_SIZE_UNKNOWN   = 0,
  LIBEC_AES_SIZE_GOOD      = 128,
  LIBEC_AES_SIZE_BETTER    = 192,
  LIBEC_AES_SIZE_BEST      = 256
} LIBEC_AES_SIZE;

// AES Defaults
#define LIBEC_AES_SIZE_ANY        LIBEC_AES_SIZE_UNKNOWN
#define LIBEC_AES_SIZE_DEFAULT    LIBEC_AES_SIZE_GOOD

// Supported Key Types
typedef enum {
  LIBEC_KEY_TYPE_UNKNOWN      = 0,
  LIBEC_KEY_TYPE_ASYMMETRIC    = 1,
  LIBEC_KEY_TYPE_SYMMETRIC    = 2
} LIBEC_KEY_TYPE;

// HMAC_VALUE memory functions
#define HMAC_VALUE_new  ASN1_OCTET_STRING_new
#define HMAC_VALUE_free ASN1_OCTET_STRING_free

// Generic Structure for a Crypto Key
typedef struct libec_crypto_key_st {
  LIBEC_KEY_TYPE   type;
  EVP_PKEY             * pkey;
  struct {
    unsigned char data[EVP_MAX_KEY_LENGTH];
    size_t        data_size;
  } skey;
} LIBEC_KEY;

// Signature Data Structure
typedef struct libec_crypto_signature_st {
  ASN1_OCTET_STRING * keyIdentifier;
  ASN1_OCTET_STRING * value;
} LIBEC_SIGNATURE;

DECLARE_ASN1_FUNCTIONS(LIBEC_SIGNATURE)

// Encrypted Data Structure
typedef struct libec_crypto_encrypted_st {
  ASN1_OCTET_STRING * keyIdentifier;
  ASN1_OCTET_STRING * encryptionKey;
  ASN1_OCTET_STRING * value;
} LIBEC_ENCRYPTED;

DECLARE_ASN1_FUNCTIONS(LIBEC_ENCRYPTED)

// Digest Structure
typedef ASN1_OCTET_STRING LIBEC_DIGEST;

// LIBEC Context Structure
typedef struct libec_crypto_context_st {
  // Signature Context
  EVP_MD_CTX   * md_ctx;
  // HMAC Context
  HMAC_CTX     * hmac_ctx;
  // Cipher Context
  EVP_CIPHER_CTX * cipher_ctx;
  // Public Key Context
  EVP_PKEY_CTX * pkey_ctx;
  // Key Pointer
  const LIBEC_KEY * key;
  // Signature Pointer
  const LIBEC_SIGNATURE * sig;
  // Encrypted Data Pointer
  const LIBEC_ENCRYPTED * enc;
  // Encrypted Key
  LIBEC_DIGEST k_enc;
  // Data That Was Encrypted
  unsigned char * enc_data;             // Data Container for Encrypted Data
  size_t          enc_data_size;        // Data Container Size
  // Data To Be Decrypted
  const unsigned char * dec_data;       // Pointer to the data to be decrypted
  const unsigned char * dec_data_next;  // Pointer to the next byte to decrypt
  size_t                dec_data_size;  // Size of the data to be decrypted
  // IV Size
  size_t enc_data_iv;       // IV Size (IV: Starts at enc_data + PREFIX)
  // TAG Size
  size_t enc_data_tag;      // TAG Size (TAG: Starts at enc_data + PREFIX + enc_data_iv)
  // Next Available Byte
  size_t enc_data_next;     // Next Empty Byte (&enc_data[enc_data_next])
  // End of the Encrypted Data
  size_t enc_data_end;
} LIBEC_CTX;

// ======================
// Generic Initialization
// ======================

void LIBEC_init();
  // Initializes the Crypto Layer

void LIBEC_cleanup();
  // Frees Crypto Resources

// =============
// Generic Tools
// =============

int LIBEC_data_cmp(const unsigned char *h1, size_t h1_size,
                         const unsigned char *h2, size_t h2_size);

// =========================
// Crypto Context Management
// =========================

LIBEC_CTX * LIBEC_CTX_new();
  // Allocates a new crypto context

int LIBEC_CTX_cleanup(LIBEC_CTX * ctx);
  // Cleanup the crypto context

void LIBEC_CTX_free(LIBEC_CTX * ctx);
  // Frees resources connected to a crypto context

// ========================
// Crypto Digest Management
// ========================

// Basic Operations on the Digest
#define LIBEC_DIGEST_new_null()  ASN1_OCTET_STRING_new()
  // Allocates a new empty DIGEST structure

#define LIBEC_DIGEST_cmp(a,b)    (a && b ? ASN1_OCTET_STRING_cmp(a,b) : 0)
  // Compares two DIGEST structures (algorithm and value)

#define LIBEC_DIGEST_free(a)    (a ? ASN1_OCTET_STRING_free(a) : 1)
  // Frees the memory associated with a DIGEST structure

void LIBEC_DIGEST_cleanup(LIBEC_DIGEST * x);

LIBEC_DIGEST * LIBEC_DIGEST_new(LIBEC_DIGEST     ** dgst,
                                            LIBEC_DIGEST_ALG    md,
                                            const unsigned char     * data,
                                            size_t                    size);

int LIBEC_DIGEST_encode(unsigned char            ** data,
                              size_t                    * size,
                              const LIBEC_DIGEST  * dgst);

LIBEC_DIGEST * LIBEC_DIGEST_decode(LIBEC_DIGEST  ** dgst,
                                               const unsigned char ** next,
                                               const unsigned char  * data,
                                               size_t                 size);

LIBEC_DIGEST_ALG LIBEC_DIGEST_algor(const LIBEC_DIGEST *dgst);

size_t LIBEC_DIGEST_value(const unsigned char       ** data,
                                const LIBEC_DIGEST   * dgst);

// =====================
// Crypto Key Management
// =====================

LIBEC_KEY * LIBEC_KEY_new();

LIBEC_KEY * LIBEC_KEY_gen_ec(LIBEC_KEY      ** key,
                                         LIBEC_EC_CURVE    curve);

LIBEC_KEY * LIBEC_KEY_gen_rsa(LIBEC_KEY      ** key,
                                          LIBEC_RSA_SIZE    bits);

LIBEC_KEY * LIBEC_KEY_gen_aes(LIBEC_KEY      ** key,
                                          LIBEC_AES_SIZE    bits);

int LIBEC_KEY_encode_public(unsigned char        ** data,
                                  size_t                * data_size,
                                  const LIBEC_KEY * key);

int LIBEC_KEY_encode_private(unsigned char        ** data,
                                   size_t                * data_size,
                                   const LIBEC_KEY * key);

LIBEC_KEY * LIBEC_KEY_decode_public(LIBEC_KEY     ** out_key,
                                                const unsigned char  * data,
                                                size_t                 data_size);

LIBEC_KEY * LIBEC_KEY_decode_private(LIBEC_KEY      ** out_key,
                                                 LIBEC_KEY_TYPE    type,
                                                 const unsigned char   * data,
                                                 size_t                  data_size);

LIBEC_DIGEST * LIBEC_KEY_identifier(LIBEC_DIGEST    ** dgst,
                                                const LIBEC_KEY  * key,
                                                LIBEC_DIGEST_ALG   alg);

void LIBEC_KEY_cleanup(LIBEC_KEY * key);

void LIBEC_KEY_free(LIBEC_KEY * key);

// ==========
// Signatures
// ==========

// Basic Operations on the SIGNATURE

#define LIBEC_SIGNATURE_cmp(a,b) \
    (a && a->value && b && b->value ? ASN1_OCTET_STRING_cmp(a->value,b->value) : 0)
  // Compares two SIGNATURE structures (algorithm and value)

int LIBEC_SIGNATURE_encode(unsigned char               ** data,
                                 size_t                       * size,
                                 const LIBEC_SIGNATURE  * dgst);

LIBEC_SIGNATURE * LIBEC_SIGNATURE_decode(LIBEC_SIGNATURE  ** dgst,
                                                     const unsigned char    ** next,
                                                     const unsigned char     * data,
                                                     size_t                    size);

int LIBEC_SIGNATURE_algor(LIBEC_ALGOR           * algor,
                                LIBEC_DIGEST_ALG      * dgst_alg,
                                const LIBEC_SIGNATURE * sig);

size_t LIBEC_SIGNATURE_value(const unsigned char         ** data,
                                   const LIBEC_SIGNATURE  * dgst);

size_t LIBEC_SIGNATURE_identifier(const unsigned char        ** data,
                                        LIBEC_DIGEST_ALG      * dgst_alg,
                                        const LIBEC_SIGNATURE * sig);

LIBEC_CTX * LIBEC_sign_init(LIBEC_CTX        ** ctx,
                                        const LIBEC_KEY   * key,
                                        LIBEC_DIGEST_ALG    dgst_alg,
                                        const unsigned char     * data,
                                        size_t                    data_size);
  // Initializes and return an signature context ('ctx'). The
  // passed 'md' is the HASH algorithm to use for the signature
  // calculation (if 'NULL', the default value is SHA256). If
  // the 'ctx' parameter is not null, then '*ctx' should hold
  // a reference to an 'EVP_MD_CTX' container that will be
  // reset to an initial state. If the 'data' and 'data_size'
  // parameters are also provide, then the signature is also
  // updated (a call to the 'LIBEC_sign_final()' would
  // generate a valid signature calculated over the 'data').
  // In case of error, the function return a NULL pointer.
  // To optimize signature generation, an application could
  // decide to re-use the 'ctx' by passing it in as the 'ctx'
  // paramer, this will avoid the need for allocating the
  // memory for the data structure.

int LIBEC_sign_update(LIBEC_CTX     * ctx,
                            const unsigned char * data,
                            size_t                data_size);
  // Updates the signature's context internal values by
  // updating the calculation of the HASH of the data for
  // final signature generation. Use this function when the
  // data to sign is not available all at once (e.g., comes
  // from the network). This function returns '1' if successful
  // and '0' in case of error.

LIBEC_SIGNATURE * LIBEC_sign_final(LIBEC_SIGNATURE ** sig,
                                               LIBEC_CTX        * ctx);
  // Finalizes the singing operation and saves the signature
  // in the '*sig' buffer of 'sig_size' size (both 'sig' and
  // 'sig_size' are output parameters, i.e. the '*sig' buffer
  // is allocated by the function). The function returns '1'
  // in case of succes, and '0' otherwise.


LIBEC_SIGNATURE * LIBEC_sign(LIBEC_CTX        ** ctx,
                                         LIBEC_SIGNATURE  ** sig,
                                         const LIBEC_KEY   * key,
                                         LIBEC_DIGEST_ALG    dgst_alg,
                                         const unsigned char     * data,
                                         size_t                    data_size);


LIBEC_CTX * LIBEC_verify_init(LIBEC_CTX             ** ctx,
                                          const LIBEC_SIGNATURE  * sig,
                                          const LIBEC_KEY        * key,
                                          const unsigned char          * data,
                                          size_t                         data_size);
  // Initializes the signature verification operation. The
  // passed 'md' is the HASH algorithm to use for the signature
  // calculation (if 'NULL', the default value is SHA256). If
  // the 'ctx' parameter is not null, then '*ctx' should hold
  // a reference to an 'EVP_MD_CTX' container that will be
  // reset to its initial state. If the 'data' and 'data_size'
  // parameters are also provided, then the verify op is also
  // updated (a call to the 'LIBEC_verify_final()' would
  // validate the signature against the provided 'data' buffer).
  // In case of error, the function return a NULL pointer.
  // To optimize signature generation, an application could
  // decide to re-use the 'ctx' by passing it in as the 'ctx'
  // paramer, this will avoid the need for allocating the
  // memory for the data structure.

int LIBEC_verify_update(LIBEC_CTX           * ctx,
                        const unsigned char * data,
                        size_t                data_size);
  // Updates the signature's context internal values by
  // updating the calculation of the HASH of the data for
  // final signature verification. Use this function when the
  // data to verify is not available all at once (e.g., comes
  // from the network). This function returns '1' if successful
  // and '0' in case of error.

int LIBEC_verify_final(LIBEC_CTX * ctx);
  // Finalizes the verification of a signature. The encoded
  // signature is provided by the caller via the 'sig' and 'sig_size'
  // parameters. The signing key (i.e. must contain the public part)
  // is provided via the 'key' parameter. This function returns '1'
  // in case the signature is successfully verified, otherwise '0'
  // is returned to indicate the error condition.

int LIBEC_verify(LIBEC_CTX             ** ctx,
                 const LIBEC_SIGNATURE  * sig,
                 const LIBEC_KEY        * key,
                 const unsigned char    * data,
                 size_t                   data_size);


// ================
// ECDH Combination
// ================

LIBEC_KEY * LIBEC_ecdh_derive(LIBEC_KEY       ** key,
                              const LIBEC_KEY  * my,
                              const LIBEC_KEY  * other);
  // This function derives a symmetric key from two Elliptic Curves
  // keys calculated over the same curve by using the ECDH algorithm.
  // The typical usage pattern is between two parties that want to
  // communicate securely. The first party generates an 'EC' key and
  // sends the Public Key to the other party who, in turn sends its
  // own public key to the first party. The two parties then can
  // derive the symmetric key independently and use that to authenticate
  // (i.e., HMAC) or encrypt (e.g., AES) messages between them.


// ==========
// Encryption
// ==========

size_t LIBEC_ENC_ALG_sym_key_size(LIBEC_ENC_ALG alg);

void LIBEC_ENCRYPTED_cleanup(LIBEC_ENCRYPTED * enc);

int LIBEC_ENCRYPTED_encode(unsigned char               ** data,
                                 size_t                 * size,
                                 const LIBEC_ENCRYPTED  * enc);

LIBEC_ENCRYPTED * LIBEC_ENCRYPTED_decode(LIBEC_ENCRYPTED     ** enc,
                                         const unsigned char ** next,
                                         const unsigned char  * data,
                                         size_t                 size);

int LIBEC_ENCRYPTED_algor(LIBEC_ENC_ALG         * algor,
                          LIBEC_ENC_MODE        * mode,
                          const LIBEC_ENCRYPTED * enc);

size_t LIBEC_ENCRYPTED_value(const unsigned char   ** data,
                             const LIBEC_ENCRYPTED  * enc);

size_t LIBEC_ENCRYPTED_identifier(const unsigned char  ** data,
                                  LIBEC_DIGEST_ALG      * dgst_alg,
                                  const LIBEC_ENCRYPTED * enc);

LIBEC_CTX * LIBEC_encrypt_init(LIBEC_CTX            ** ctx,
                               const LIBEC_KEY       * d_key,
                               LIBEC_ENC_ALG           algor,
                               LIBEC_ENC_MODE          mode,
                               const unsigned char   * data,
                               size_t                  data_size);

int LIBEC_encrypt_update(LIBEC_CTX                 * ctx,
                               const unsigned char * data,
                               size_t                data_size);

LIBEC_ENCRYPTED * LIBEC_encrypt_final(LIBEC_ENCRYPTED ** enc,
                                      LIBEC_CTX        * ctx);

LIBEC_ENCRYPTED * LIBEC_encrypt(LIBEC_CTX           ** ctx,
                                LIBEC_ENCRYPTED     ** enc,
                                LIBEC_KEY            * key,
                                LIBEC_ENC_ALG          algor,
                                LIBEC_ENC_MODE         mode,
                                const unsigned char  * data,
                                size_t                 data_size);

LIBEC_CTX * LIBEC_decrypt_init(LIBEC_CTX             ** ctx,
                               unsigned char         ** buffer,
                               size_t                 * buffer_size,
                               const LIBEC_ENCRYPTED  * enc,
                               const LIBEC_KEY        * key);

int LIBEC_decrypt_update(unsigned char               ** data,      /* OUT    */
                               size_t                 * data_size, /* IN/OUT */
                               const LIBEC_ENCRYPTED  * enc,       /* Unused */
                               LIBEC_CTX              * ctx);

int LIBEC_decrypt_final(unsigned char ** data,
                        size_t         * size,
                        LIBEC_CTX      * ctx);

LIBEC_CTX * LIBEC_decrypt(LIBEC_CTX             ** ctx,
                          unsigned char         ** data,
                          size_t                 * size,
                          const LIBEC_ENCRYPTED  * enc,
                          const LIBEC_KEY        * key);

LIBEC_CTX * LIBEC_encrypt_sym_direct(LIBEC_CTX           ** ctx,
                                     unsigned char       ** enc_data,
                                     size_t               * enc_data_size,
                                     LIBEC_KEY            * key,
                                     LIBEC_ENC_ALG          algor,
                                     LIBEC_ENC_MODE         mode,
                                     const unsigned char  * data,
                                     size_t                 data_size);

LIBEC_CTX * LIBEC_decrypt_sym_direct(LIBEC_CTX           ** ctx,
                                     unsigned char       ** data,
                                     size_t               * data_size,
                                     const unsigned char  * enc,
                                     size_t                 enc_size,
                                     const LIBEC_KEY      * key);

END_C_DECLS


#endif
