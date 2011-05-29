#include <libec/libec.h>

#define DEBUG(a) \
  fprintf(stderr, "[DEBUG: %s/%d/%s] " a "\n", __FILE__, __LINE__, __PRETTY_FUNCTION__)

#ifdef  __cplusplus
extern "C" {
#endif

// Global Engine Variable
ENGINE *rand_eng = NULL;

#ifndef LIBEC_DIGEST_PREFIX_SIZE
# define LIBEC_DIGEST_PREFIX_SIZE		1
#endif

#ifndef LIBEC_SIGNATURE_PREFIX_SIZE
# define LIBEC_SIGNATURE_PREFIX_SIZE	1
#endif

#ifndef LIBEC_ENCRYPTED_PREFIX_SIZE
# define LIBEC_ENCRYPTED_PREFIX_SIZE	1
#endif

#ifndef LIBEC_ENCRYPTED_PREALLOC_BLOCK
#define LIBEC_ENCRYPTED_PREALLOC_BLOCK  16384
#endif

// TODO: DEBUG MACRO - TO BE REMOVED
//
// a ....: FILE * where to write to (e.g., stderr)
// v ....: Name/Identifier for the data to be debugged
// b ....: Pointer to the Unsigned Char buffer
// c ....: Size (bytes) of the buffer to dump
#define DEBUG_UNSIGNED(a,v,b,c)                              \
    {   size_t _idx;                                         \
        fprintf(a, "[%s::%d::%s()] %s (%llu) = { \n", __FILE__, __LINE__, __PRETTY_FUNCTION__, v, c); \
        fprintf(a, "[%s::%d::%s()]     ", __FILE__, __LINE__,  __PRETTY_FUNCTION__); \
        unsigned char * k = (unsigned char *)b;              \
        for (_idx = 1; _idx <= (size_t) c; _idx++) {          \
           unsigned char cHR;                                \
           cHR = (unsigned char) k[_idx -1];                 \
           fprintf(a, "0x%2.2x", cHR);                       \
           if (_idx <= (size_t) c) fprintf(a, " ");          \
           else fprintf(a, "\n");                            \
           if (_idx > 0 && _idx < (size_t) c - 1 && _idx % 8 == 0) \
         fprintf(a, "\n[%s::%d::%s()]     ", __FILE__, __LINE__,  __PRETTY_FUNCTION__);  \
        }                                                    \
        fprintf(a, "\n[%s::%d::%s()]   }\n", __FILE__, __LINE__,  __PRETTY_FUNCTION__); \
    }

#define DEBUG_OSSL_ERROR(a)                                   \
        {                                                     \
          int err = ERR_get_error();                          \
          if (err) {                                          \
            fprintf(a, "%s:%d DEBUG\n", __FILE__, __LINE__);  \
            fprintf(a, "\n%s:%d DEBUG: OSS ERROR = %s\n\n",   \
                __FILE__, __LINE__,                           \
                ERR_error_string(ERR_get_error(), NULL));     \
            ERR_clear_error();                                \
          }                                                   \
        }

#define ASN1_OCTET_STRING_cleanup   LIBEC_DIGEST_cleanup

// ================
// Static Variables
// ================

static pthread_mutex_t *lock_cs;
static long *lock_count;

// ================
// ASN1_DEFINITIONS
// ================

ASN1_SEQUENCE(LIBEC_SIGNATURE) = {
	ASN1_SIMPLE(LIBEC_SIGNATURE, keyIdentifier, ASN1_OCTET_STRING),
	ASN1_SIMPLE(LIBEC_SIGNATURE, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(LIBEC_SIGNATURE)

IMPLEMENT_ASN1_FUNCTIONS(LIBEC_SIGNATURE)

ASN1_SEQUENCE(LIBEC_ENCRYPTED) = {
	ASN1_SIMPLE(LIBEC_ENCRYPTED, keyIdentifier, ASN1_OCTET_STRING),
  ASN1_SIMPLE(LIBEC_ENCRYPTED, encryptionKey, ASN1_OCTET_STRING),
	ASN1_SIMPLE(LIBEC_ENCRYPTED, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(LIBEC_ENCRYPTED)

IMPLEMENT_ASN1_FUNCTIONS(LIBEC_ENCRYPTED)

// ================
// Static Functions
// ================

static inline HMAC_CTX * HMAC_CTX_new() {
	return (HMAC_CTX *) OPENSSL_malloc(sizeof(HMAC_CTX));
}

static inline void HMAC_CTX_free(HMAC_CTX * ctx) {
	if (ctx) OPENSSL_free(ctx);
}

void pthreads_locking_callback(int mode, int type, char *file, int line);
unsigned long pthreads_thread_id(void);

void pthreads_locking_callback(int mode, int type, char *file, int line) {

  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(lock_cs[type]));
    lock_count[type]++;
  } else {
    pthread_mutex_unlock(&(lock_cs[type]));
  }

  return;
}

unsigned long pthreads_thread_id(void) {
  unsigned long ret;

  ret=(unsigned long)pthread_self();
  return(ret);
}


// ==============
// Key Generation
// ==============

static int _get_iv_length(const EVP_CIPHER * cipher) {

  return 16;

  // if (cipher) return EVP_CIPHER_iv_length(cipher);
};

static EVP_PKEY * _gen_rsa(LIBEC_RSA_SIZE bits) {

	// Generates a new RSA key of the specified size.
	// The function returns a pointer to a valid 'EVP_PKEY'
	// structure in case of success or the 'NULL' value
	// in case of errors

	RSA * rsa = NULL;
		// EC Key

	EVP_PKEY * ret = NULL;
		// Generic EVP Key

    BIGNUM *bne = NULL;
    	// BIGNUM container

    int ossl_rc = 0;
    	// OSSL ret

    unsigned long e = RSA_F4;
    	// Default exponent (65537)

    if ((bne = BN_new()) != NULL) {
    	// Sets the Right Value in the BN
    	if (1 != BN_set_word(bne,e)) goto err;
    } else {
    	// Memory Error
    	goto err;
    }

    // Apply the default
    if (bits == 0) bits = LIBEC_RSA_SIZE_DEFAULT;

    // Allocates a new RSA structure
    if ((rsa = RSA_new()) == NULL) goto err;

	// Generates the RSA key
	if ((ossl_rc = RSA_generate_key_ex(rsa, bits, bne, NULL)) == 1) {
		// Let's free the BN
		BN_free(bne);
		bne = NULL;
	} else {
		// Error Generating the Key
		goto err;
	}

	// Allocates a new generic container
	if ((ret = EVP_PKEY_new()) == NULL) goto err;

	// Assigns the EC key to the generic container
	if (!EVP_PKEY_assign_RSA(ret, rsa)) goto err;

	// All Done
	return ret;

err:

	if (bne) BN_free(bne);
	if (rsa) RSA_free(rsa);
	if (ret) EVP_PKEY_free(ret);

	return NULL;
}

static EVP_PKEY * _gen_ec(LIBEC_EC_CURVE nid) {

	// Generates a new EC key by using the passed
	// identifier for the EC curve to be used. The
	// function returns a pointer to a valid 'EVP_PKEY'
	// structure in case of success or the 'NULL' value
	// in case of errors.

	EC_KEY * ec = NULL;
		// EC Key

	EVP_PKEY * ret = NULL;
		// Generic EVP Key

	// Use default if no choice was made
	// if (nid <= 0) nid = NID_secp224r1;
	if (nid <= 0) nid = LIBEC_EC_CURVE_DEFAULT;

	// Allocate a new curve
	if ((ec = EC_KEY_new_by_curve_name(nid)) == NULL) goto err;

	// Pick the private and public keys
	if (EC_KEY_generate_key(ec) != 1) goto err;

	// Allocates a new generic container
	if ((ret = EVP_PKEY_new()) == NULL) goto err;

	// Assigns the EC key to the generic container
	if (!EVP_PKEY_assign_EC_KEY(ret, ec)) goto err;

	// All Done
	return ret;

err:

	ERR_print_errors_fp(stderr);

	if (ec) EC_KEY_free(ec);
	if (ret) EVP_PKEY_free(ret);

	return NULL;
}

static int _pubkey_encode(EVP_PKEY       * key,
		                      unsigned char ** out_data,
		                      size_t         * out_size) {

	// Encodes the public 'key' and saves it in 'key_data'
	// of 'key_size' length (both 'out' parameters, i.e.
	// the buffer is allocated by the function).

	// Input Check
	if (!key || !out_data || !out_size) return 0;

	// Make sure we have a zeroized pointer
	*out_data = NULL;

	if ((*out_size = (size_t) i2d_PUBKEY(key, out_data)) > 0) {
		// Success
		return 1;
	}

	// Error
	return 0;
}

static EVP_PKEY * _pubkey_decode(EVP_PKEY            ** pkey,
								 const unsigned char  * data,
		                         size_t                 size) {
	// Parses a public key and returns it to the caller.
	// The data should hold a DER representation of the
	// public key structure. This function returns a valid
	// pointer to an 'EVP_PKEY' structure if successful and
	// the 'NULL' value in case of errors.

	EVP_PKEY * ret = NULL;
		// Return Container

	const unsigned char * tmp_pnt = NULL;
		// Copy Pointer to avoid OpenSSL's
		// pointer advancement

	// Input Check
	if (!data || size == 0) return 0;

	// Copy the Pointer
	tmp_pnt = data;

	// Decodes the Key
	if ((ret = d2i_PUBKEY(pkey, &tmp_pnt, size)) == NULL) {
		// Error while decoding
		return NULL;
	}

	// Success
	return ret;
}

static int _privkey_encode(EVP_PKEY       * key,
		                       unsigned char ** out_data,
		                       size_t         * out_size) {

	// Encodes the private part of the passed 'key' in DER
	// format and saves the output in the 'data' buffer of
	// 'size' length (both 'data' and 'size' are output
	// parameters, i.e. the '*data' buffer is allocated by
	// the function). In case of success, this function
	// returns '1', otherwise it returns '0' (in case of
	// errors)

	BIO * mem_bio = NULL;
	BUF_MEM * buf_mem = NULL;
		// I/O Facility

	// Input Check
	if (!key || !out_data || !out_size) return 0;

	// Make sure we have a zeroized pointer
	*out_data = NULL;
	*out_size = 0;

	// Creates a new Mem Bio
	if ((mem_bio = BIO_new(BIO_s_mem())) != NULL) {
		// Writes the data to be BIO
		if (i2d_PrivateKey_bio(mem_bio, key) > 0) {
			// Gets the internal buffer
			BIO_get_mem_ptr(mem_bio, &buf_mem);
			// Copy the Memory
			if (buf_mem->data != NULL && buf_mem->length > 0) {
				// Assigns the data to the output parameter
				if ((*out_data = (unsigned char *) OPENSSL_malloc(buf_mem->length)) != NULL) {
					// Copy the Memory
					memcpy(*out_data, buf_mem->data, buf_mem->length);
					// Sets the size
					*out_size = buf_mem->length;
					// Free the Memory
					BIO_free_all(mem_bio);
					// Success
					return 1;
				}
			}
		}
	}

	// If we reach here, we had an error
	if (mem_bio) BIO_free_all(mem_bio);

	// Error
	return 0;
}

static int _privkey_encode_sym(unsigned char       ** data,
		                           size_t               * data_size,
                               const unsigned char  * key,
                               size_t                 key_size) {

	ASN1_OCTET_STRING val;
		// Temporary Container

	unsigned char * tmp_pnt;
		// Pointer for parsing the ASN1 structure

	// Input check
	if (!data || !data_size || !key || !key_size) return 0;

	// Zeroizes the ASN1 data structure
	memset(&val, 0, sizeof(ASN1_OCTET_STRING));

    // Assigns the value to the value field
    if (1 != ASN1_OCTET_STRING_set(&val, key, key_size)) return 0;

    // Gets the size of the encoded value
    if ((*data_size = i2d_ASN1_OCTET_STRING(&val, NULL)) <= 0) return 0;

    // Let's allocate the required memory
    if ((*data = OPENSSL_malloc(*data_size)) == NULL) return 0;

    // Encodes the value
    tmp_pnt = *data;
    i2d_ASN1_OCTET_STRING(&val, &tmp_pnt);

    // Clears the string
    ASN1_STRING_set0(&val, NULL, 0);

    // All Done
    return 1;

err:

	// Memory Cleanup
	if (*data) {
		OPENSSL_cleanse(*data, *data_size);
		OPENSSL_free(*data);
		*data = NULL;
	}

	// Output Parameters Cleanup
	if (*data_size) *data_size = 0;

	// Error
	return 0;
}

EVP_PKEY * _privkey_decode(const unsigned char * data,
                           size_t                size) {

	// Parses a private key and returns it to the caller.
	// The data should hold the DER representation of the
	// private key structure. This function returns a valid
	// pointer to an 'EVP_PKEY' structure if successful and
	// the 'NULL' value in case of errors

	EVP_PKEY * ret = NULL;
		// Return Container

	BIO * mem_bio = NULL;
		// BIO Container

	// Input Check
	if (!data || size == 0) return 0;

	// Creates a new Mem Bio
	if ((mem_bio = BIO_new(BIO_s_mem())) != NULL) {
		// Writes the data to be BIO
		if (BIO_write(mem_bio, data, size) > 0) {
			// Decodes the Key
			if ((ret = d2i_PrivateKey_bio(mem_bio, NULL)) == NULL) {
				// Error
				goto err;
			}
		}
	}

	// Free the Memory associated with the BIO
	if (mem_bio) BIO_free(mem_bio);

	// Success
	return ret;

err:

	ERR_print_errors_fp(stderr);

	if (mem_bio) BIO_free(mem_bio);
	if (ret) EVP_PKEY_free(ret);

	return NULL;
}

static int _privkey_decode_sym(unsigned char       * key,
                               size_t              * key_size,
                               const unsigned char * data,
                               size_t                data_size) {

	ASN1_OCTET_STRING val;
	ASN1_OCTET_STRING * val_pnt = NULL;
		// Temporary Container

	const unsigned char * tmp_pnt = NULL;
		// Pointer for parsing the ASN1 structure

  size_t ret_size = 0;

	// Input check
	if (!data || !data_size || !key || !key_size) return 0;

	// Zeroizes the ASN1 data structure
	memset(&val, 0, sizeof(ASN1_OCTET_STRING));

	// Parses the HMAC value
	val_pnt = &val;
	tmp_pnt = data;
	if (NULL == d2i_ASN1_OCTET_STRING(&val_pnt, &tmp_pnt, data_size)) return 0;

  // Gets the size of data to be copied over
  ret_size = val.length > EVP_MAX_KEY_LENGTH ? EVP_MAX_KEY_LENGTH : val.length;

	// Copy the data to the caller
  memcpy(key, val.data,ret_size);
	*key_size = ret_size;

  // Cleanse the Memory
  OPENSSL_cleanse(val.data, val.length);
  OPENSSL_free(val.data);

  // All Done
  return 1;
}

static int _get_md_nid(int v) {

	// Returns the NID for the supported algorithm
	switch (v & LIBEC_DIGEST_ALG_MASK) {

		case LIBEC_DIGEST_ALG_SHA256: {
			return NID_sha256;
		} break;

		case LIBEC_DIGEST_ALG_SHA384: {
			return NID_sha256;
		} break;

		case LIBEC_DIGEST_ALG_SHA512: {
			return NID_sha512;
		} break;

		default: {
			break;
		}
	}

	return NID_undef;
}

static const EVP_MD * _get_evp_md(int v) {

	// Returns the NID for the supported algorithm
	switch (v & LIBEC_DIGEST_ALG_MASK) {

		case LIBEC_DIGEST_ALG_SHA256: {
			return EVP_sha256();
		} break;

		case LIBEC_DIGEST_ALG_SHA384: {
			return EVP_sha384();
		} break;

		case LIBEC_DIGEST_ALG_SHA512: {
			return EVP_sha512();
		} break;

		default: {
			break;
		}
	}

	return NID_undef;
}

static int _get_pkey_type(int v) {

	switch (v & LIBEC_ALGOR_MASK) {

		case LIBEC_ALGOR_RSA: {
			return EVP_PKEY_RSA;
		} break;

		case LIBEC_ALGOR_ECDSA: {
			return EVP_PKEY_EC;
		} break;

		default: {
			break;
		}
	}

	return NID_undef;
}

static const EVP_CIPHER * _get_evp_cipher(int v) {

	// Returns the NID for the supported algorithm
	switch (v & LIBEC_ENC_ALG_MASK) {

    // 128 Bit AES Encryption
		case LIBEC_ENC_ALG_AES_128: {

		  switch( v & LIBEC_ENC_MODE_MASK) {
		    case LIBEC_ENC_MODE_GCM : {
		      return EVP_aes_128_gcm();
		    } break;

		    case LIBEC_ENC_MODE_CBC : {
          return EVP_aes_128_cbc();
		    } break;

		    default:
		      break;
		  }
		} break;

    // 192 Bit AES Encryption
		case LIBEC_ENC_ALG_AES_192: {

      switch( v & LIBEC_ENC_MODE_MASK) {
        case LIBEC_ENC_MODE_GCM : {
          return EVP_aes_192_gcm();
        } break;

        case LIBEC_ENC_MODE_CBC : {
          return EVP_aes_192_cbc();
        } break;

        default:
          break;
      }

		} break;

    // 256 Bit AES Encryption
		case LIBEC_ENC_ALG_AES_256: {

      switch( v & LIBEC_ENC_MODE_MASK) {
        case LIBEC_ENC_MODE_GCM : {
          return EVP_aes_256_gcm();
        } break;

        case LIBEC_ENC_MODE_CBC : {
          return EVP_aes_256_cbc();
        } break;

        default:
          break;
      }

		} break;

		default: {
			break;
		}
	}

	return NID_undef;
}

size_t _get_identifier(const unsigned char    ** data,
                       LIBEC_DIGEST_ALG  * dgst_alg,
                       LIBEC_DIGEST      * x_k) {
  size_t ret = 0;

	// Input Check
	if (!x_k || !x_k->data) return 0;

	// Sets the output pointer (after the prefix)
	if (data) *data = x_k->data + LIBEC_SIGNATURE_PREFIX_SIZE;

  // Sets the output algorithm value
  if (dgst_alg) *dgst_alg = x_k->data[0] & LIBEC_DIGEST_ALG_MASK;

	// Returns the size (minus the prefix len)
	return (size_t) x_k->length - LIBEC_SIGNATURE_PREFIX_SIZE;
}

// ==============================
// Internal Encryption/Decryption
// ==============================

LIBEC_CTX * _encrypt_init_sym(LIBEC_CTX      ** ctx,
                                    LIBEC_ENC_ALG     alg,
                                    LIBEC_ENC_MODE    mode,
                                    const unsigned char   * key_data,
                                    size_t                  key_data_size) {

  LIBEC_CTX * ret = NULL;
    // Return Structure

  const EVP_CIPHER * cipher = NULL;
    // OpenSSL Cipher Implementation

  // Input Check
  if (!key_data || !key_data_size) return NULL;

  // Setup the Container's pointers
  if (ctx && *ctx) {
    // Use the passed container
    ret = *ctx;
    // Cleanup the Key
    LIBEC_CTX_cleanup(ret);
  } else {
    // Allocates the memory for the container
    if ((ret = LIBEC_CTX_new()) == NULL) return NULL;
  }

  // Encryption algorithm and mode
  if (!alg) alg = LIBEC_ENC_ALG_DEFAULT;
  if (!mode) mode = LIBEC_ENC_MODE_DEFAULT;

  // Gets the requested cipher
  if ((cipher = _get_evp_cipher(alg | mode)) == NULL) goto err;

  // Gets the Size of the TAG (for AEAD ciphers)
  ret->enc_data_tag = LIBEC_ENC_ALG_tag_size(mode);

  // Gets the IV size
  if ((ret->enc_data_iv = _get_iv_length(cipher)) <= 0) goto err;

  // Initializes the CTX
  EVP_CIPHER_CTX_init(ret->cipher_ctx);

  // Gets the size of the initial buffer to allocate
  ret->enc_data_size = LIBEC_ENCRYPTED_PREFIX_SIZE     + // Prefix Size
                       ret->enc_data_iv                      + // IV Size
                       ret->enc_data_tag                     + // TAG Size
                       EVP_CIPHER_block_size(cipher)         + // (Eventual) Padding block
                       LIBEC_ENCRYPTED_PREALLOC_BLOCK;   // Let's Pre-Allocate some space

  // Allocates the memory
  if ((ret->enc_data = OPENSSL_malloc(ret->enc_data_size)) == NULL) goto err;

  // Sets the Algorithm and Mode
  ret->enc_data[0] = (uint8_t) (alg | mode);
  ret->enc_data_next = LIBEC_ENCRYPTED_PREFIX_SIZE;

  // Generates the IV data
  if (!RAND_bytes(ret->enc_data + ret->enc_data_next, ret->enc_data_iv)) goto err;

  ret->enc_data_next += ret->enc_data_iv;

  // If AEAD is used, let's skip the TAG
  ret->enc_data_next += ret->enc_data_tag;

  // We create the Symmetric Encryption Key
  if(1 != EVP_EncryptInit_ex(ret->cipher_ctx,
                             cipher,
                             NULL,
                             NULL,
                             NULL)) goto err;

#ifdef EVP_CTRL_GCM_SET_IVLEN

  if (ret->enc_data_tag > 0) {

    if (!EVP_CIPHER_CTX_ctrl(ret->cipher_ctx,
                             EVP_CTRL_GCM_SET_IVLEN,
                             ret->enc_data_iv,
                             NULL)) goto err;
  }
#endif

  // We create the Symmetric Encryption Key
  if(1 != EVP_EncryptInit_ex(ret->cipher_ctx,
                             NULL,
                             NULL,
                             (const unsigned char *)key_data,
                             ret->enc_data + LIBEC_ENCRYPTED_PREFIX_SIZE)) goto err;

  // Fix the output parameter
  if (ctx) *ctx = ret;

  // Success
  return ret;

err:

  // Cleanup The Context
  if (ret) LIBEC_CTX_cleanup(ret);

  // Free Memory and Fix output params
  if (!(ctx && *ctx)) {
    if (ret) LIBEC_CTX_free(ret);
    if (ctx) *ctx = NULL;
  }

  // Error
  return NULL;
}

int _encrypt_final_sym(LIBEC_CTX * ctx) {

  int outl = 0;
    // Written Output Bytes

  // Input Check
  if (!ctx || !ctx->enc_data || !ctx->enc_data_size) return 0;

  // Finalizes the Encryption
  if (ctx->enc_data_size < ctx->enc_data_next
                             + EVP_CIPHER_CTX_block_size(ctx->cipher_ctx)) {

    // Reallocate with enough space
    ctx->enc_data = realloc(ctx->enc_data,
                            ctx->enc_data_size
                              + EVP_CIPHER_CTX_block_size(ctx->cipher_ctx));

    // Updates the size
    ctx->enc_data_size += EVP_CIPHER_CTX_block_size(ctx->cipher_ctx);
  }

  // Finalizes the Encryption
  if (1 != EVP_EncryptFinal_ex(ctx->cipher_ctx,
                               ctx->enc_data
                               + ctx->enc_data_next,
                               &outl)) return 0;

  // Updates the end of the encrypted data
  ctx->enc_data_end  = ctx->enc_data_next + outl;
  ctx->enc_data_next = 0;

#ifdef EVP_CTRL_GCM_GET_TAG

if (ctx->enc_data_tag > 0) {
  // Sets the TAG in the output buffer
  if (!EVP_CIPHER_CTX_ctrl(ctx->cipher_ctx,
                           EVP_CTRL_GCM_GET_TAG,
                           LIBEC_AEAD_TAG_LENGTH,
                           ctx->enc_data
                           + LIBEC_ENCRYPTED_PREFIX_SIZE
                           + ctx->enc_data_iv)) return 0;
}
#endif

  // Success
  return 1;
}

ASN1_OCTET_STRING * _encrypt_key(ASN1_OCTET_STRING     ** out,
                                 unsigned char         ** key_data,
                                 size_t                 * key_data_size,
                                 const LIBEC_KEY  * d_key,
                                 LIBEC_ENC_ALG      alg,
                                 LIBEC_ENC_MODE     mode) {

  ASN1_OCTET_STRING * ret = NULL;
    // Return Structure

  LIBEC_CTX * ctx = NULL;
    // Crypto Ctx

  int outl = 0;
  size_t outs = 0;
    // Encrypted data output

  // Input Check
  if (!d_key | !key_data | !key_data_size) return NULL;

  // Encryption algorithm and mode
  if (!alg) alg = LIBEC_ENC_ALG_DEFAULT;
  if (!mode) mode = LIBEC_ENC_MODE_DEFAULT;

  // Setup the Container's pointers
  if (out && *out) {
    // Use the passed container
    ret = *out;
    // Cleanup the Key
    ASN1_OCTET_STRING_cleanup(ret);
  } else {
    // Allocates the memory for the container
    if ((ret = ASN1_OCTET_STRING_new()) == NULL) return NULL;
  }

  // Gets the size of the encryption key
  *key_data_size = LIBEC_ENC_ALG_sym_key_size(alg);

  // Allocates the required memory
  if ((*key_data = OPENSSL_malloc(*key_data_size)) == NULL) goto err;

  // Generates the random key
  if (!RAND_bytes(*key_data, *key_data_size)) goto err;

  // Now we can perform the Encryption
  switch (d_key->type) {

    case LIBEC_KEY_TYPE_ASYMMETRIC : {

      // Simple Check
      if (!d_key->pkey) return 0;

      switch (EVP_PKEY_type(d_key->pkey->type)) {

        // RSA Keys
        case EVP_PKEY_RSA: {

          // Gets the Public Key Context
          if ((ctx = LIBEC_CTX_new()) == NULL) goto err;

          // Allocates the Public Key Context
          if ((ctx->pkey_ctx = EVP_PKEY_CTX_new(d_key->pkey, NULL)) == NULL) goto err;

          // Initializes the Encryption (only works with RSA)
          if (1 != EVP_PKEY_encrypt_init(ctx->pkey_ctx)) goto err;

          // Gets the size of the final encryption
          if (EVP_PKEY_encrypt(ctx->pkey_ctx, NULL, &outs, *key_data, *key_data_size) <= 0) goto err;

          // Allocates the required space
          if ((ctx->enc_data = OPENSSL_malloc(outs + LIBEC_ENCRYPTED_PREFIX_SIZE)) == NULL) goto err;
          ctx->enc_data_size = outs + LIBEC_ENCRYPTED_PREFIX_SIZE;

          // Sets the Encryption Algorithm to RSA
          ctx->enc_data[0] = (uint8_t) LIBEC_ENC_ALG_RSA;
          ctx->enc_data_next = LIBEC_ENCRYPTED_PREFIX_SIZE;

          // Gets the output size for the encryption of the key
          if (EVP_PKEY_encrypt(ctx->pkey_ctx,
                               ctx->enc_data + ctx->enc_data_next,
                               &outs,
                               *key_data,
                               *key_data_size) <= 0) goto err;

          // Updates the end of the buffer
          ctx->enc_data_end  = ctx->enc_data_next + outs;
          ctx->enc_data_next = 0;

          // Transfer the data
          ret->data = ctx->enc_data;
          ret->length = ctx->enc_data_end;

          // Removes data from the context
          ctx->enc_data = NULL;
          ctx->enc_data_size = 0;

          // Success!

        } break;

        // EC Keys
        case EVP_PKEY_EC : {

          // This case is a bit more complex, because we need to generate another point
          // on the curve, then use the destination key (d_key) and the ephemeral key (d_eph)
          // to derive the encryption key that will be used to encrypt the message
          fprintf(stderr, "ERROR: Encrypting for an EC key is NOT Implemented!\n");
          goto err;

        } break;

        default : {
          // ERROR
          goto err;
        }
      }

    } break;

    case LIBEC_KEY_TYPE_SYMMETRIC : {

      // Initializes the Symmetric Encryption
      if (NULL == _encrypt_init_sym(&ctx,
                                     alg,
                                     mode,
                                     d_key->skey.data,
                                     d_key->skey.data_size)) goto err;

      // Eventually Re-Allocate The Encrypted data pointer in the CTX
      if (*key_data_size > ctx->enc_data_size - ctx->enc_data_next) {
        size_t new_size = 0;

        // Gets the new size
        new_size = ctx->enc_data_size
                   + *key_data_size
                   + EVP_CIPHER_CTX_block_size(ctx->cipher_ctx);

        // Resize the buffer
        if ((ctx->enc_data = realloc(ctx->enc_data, new_size)) == NULL) goto err;

        // Updates the size of the buffer
        ctx->enc_data_size = new_size;
      }

      // Actually Encrypts the Data
      if (1 != EVP_EncryptUpdate(ctx->cipher_ctx,
                                 ctx->enc_data + ctx->enc_data_next,
                                 &outl,
                                 *key_data,
                                 *key_data_size)) goto err;
      ctx->enc_data_next += outl;

      // Finalizes the Encryption
      if (1 != _encrypt_final_sym(ctx)) goto err;

      // Transfers the encrypted data buffer
      ret->data = ctx->enc_data;
      ret->length = ctx->enc_data_end;

      // Cleanup the CTX
      ctx->enc_data = NULL;

      // All Done
    } break;

    default : {
      // Not Recognize Key Type
      goto err;
    }
  }


  // Free resources
  if (ctx) LIBEC_CTX_free(ctx);

  // Sets the output parameter
  if (out) *out = ret;

  // Success
  return ret;

err:

  // Free the Public Key Context
  if (ctx) LIBEC_CTX_free(ctx);

  // Free (if allocated) output structure
  if (!(out && *out)) {
    if (ret) ASN1_OCTET_STRING_free(ret);
    *out = NULL;
  }

  // Zeroize the data
  *key_data = NULL;
  *key_data_size = 0;

  // Reports the error
  return NULL;
}

LIBEC_CTX * _decrypt_init_sym(LIBEC_CTX     ** ctx,
                                    const unsigned char  * enc_data,
                                    size_t                 enc_data_size,
                                    const unsigned char  * key_data,
                                    size_t                 key_data_size) {

  LIBEC_CTX * ret = NULL;
    // Return Structure

  const EVP_CIPHER * cipher = NULL;
    // OpenSSL's Cipher Reference

  // Input Checks
  if (!enc_data || !enc_data_size || !key_data || !key_data_size) return NULL;

  // Setup the Container's pointers
  if (ctx && *ctx) {
    // Use the passed container
    ret = *ctx;
    // Cleanup the Key
    LIBEC_CTX_cleanup(ret);
  } else {
    // Allocates the memory for the container
    if ((ret = LIBEC_CTX_new()) == NULL) return NULL;
  }

  // Initializes the CTX
  EVP_CIPHER_CTX_init(ret->cipher_ctx);

  // Gets the requested cipher
  if ((cipher = _get_evp_cipher(enc_data[0])) == NULL) goto err;

  // Gets the size of the TAG
  ret->enc_data_tag = LIBEC_ENC_ALG_tag_size(enc_data[0]);

  // Gets the size of the IV
  if ((ret->enc_data_iv = _get_iv_length(cipher)) <= 0) goto err;

  // We create the Symmetric Encryption Key
  if(1 != EVP_DecryptInit_ex(ret->cipher_ctx,
                             cipher,
                             NULL,
                             NULL,
                             NULL)) goto err;

#ifdef EVP_CTRL_GCM_SET_IVLEN

  // If GCM mode, we need to set the size of the IV
  if (ret->enc_data_tag > 0) {

    if (!EVP_CIPHER_CTX_ctrl(ret->cipher_ctx,
                             EVP_CTRL_GCM_SET_IVLEN,
                             ret->enc_data_iv,
                             NULL)) goto err;
  }
#endif

  // We create the Symmetric Encryption Key
  if(1 != EVP_DecryptInit_ex(ret->cipher_ctx,
                             NULL,
                             NULL,
                             key_data,
                             enc_data + LIBEC_ENCRYPTED_PREFIX_SIZE)) goto err;

  // Gets the beginning and size of the data to be decrypted
  ret->dec_data      =   enc_data;
  ret->dec_data_size = enc_data_size;

  // Sets the pointer to the next byte to be decrypted
  ret->dec_data_next =   enc_data
                       + LIBEC_ENCRYPTED_PREFIX_SIZE
                       + ret->enc_data_iv
                       + ret->enc_data_tag;

  // Fixes the output parameter
  if (ctx) *ctx = ret;

  // Success
  return ret;

err:

  // Free Memory
  if (!(ctx && *ctx)) {
    if (ret) LIBEC_CTX_free(ret);
    *ctx = NULL;
  }

  // Report the Error
  return NULL;
}

int _decrypt_final_sym(unsigned char * data, size_t *size, LIBEC_CTX *ctx) {

  int outl;

  // Input Check
  if (!data || !size || !ctx) return 0;

#ifdef EVP_CTRL_GCM_GET_TAG

  if (ctx->enc_data_tag > 0) {

    // Set expected tag value
    if(!EVP_CIPHER_CTX_ctrl(ctx->cipher_ctx,
                            EVP_CTRL_GCM_SET_TAG,
                            ctx->enc_data_tag,
                            (void *)ctx->dec_data
                              + LIBEC_ENCRYPTED_PREFIX_SIZE
                              + ctx->enc_data_iv)) return 0;
  }
#endif

  // Finalizes the Decryption
  if (1 != EVP_DecryptFinal_ex(ctx->cipher_ctx, data + *size, &outl)) return 0;
  *size += outl;

  // All Done
  return 1;
}

LIBEC_KEY * _decrypt_key(LIBEC_CTX       ** ctx,
                               LIBEC_KEY       ** out,
                               ASN1_OCTET_STRING      * enc_data,
                               const LIBEC_KEY  * d_key) {

  LIBEC_KEY * ret = NULL;
    // Return Structure

  const EVP_CIPHER * cipher   = NULL;
    // HMAC Message Digest

  LIBEC_CTX * inner_ctx = NULL;
    // Crypto Context

  int    outd           = 0;
  size_t outl           = 0;
  size_t dec_data_size  = 0;
  size_t enc_data_size  = 0;
  size_t enc_data_begin = 0;
    // Decrypted data output

  LIBEC_ENC_ALG alg   = 0;
  LIBEC_ENC_MODE mode = 0;
    // Encryption Algorithm and Mode

  unsigned char tmp_buf[3072];
    // Buffer for PubKey Decryption

  unsigned char * tmp_pnt = NULL;
    // Temporary Pointer

  // Input Check
  if (!d_key || !enc_data || !enc_data->data || enc_data->length < 1) return NULL;

  // Gets the Algor and Mode
  alg = enc_data->data[0] & LIBEC_ENC_ALG_MASK;
  mode = enc_data->data[0] & LIBEC_ENC_MODE_MASK;

  // Setup the Container's pointers
  if (out && *out) {
    // Use the passed container
    ret = *out;
    // Cleanup the Key
    LIBEC_KEY_cleanup(ret);
  } else {
    // Allocates the memory for the container
    if ((ret = LIBEC_KEY_new()) == NULL) return NULL;
  }

  // Setup the Container's pointers
  if (ctx && *ctx) {
    // Use the passed container
    inner_ctx = *ctx;
    // Cleanup the Key
    LIBEC_CTX_cleanup(inner_ctx);
  } else {
    // Allocates the memory for the container
    if ((inner_ctx = LIBEC_CTX_new()) == NULL) return NULL;
  }

  // Now we can perform the Encryption
  switch (d_key->type) {

    case LIBEC_KEY_TYPE_ASYMMETRIC : {

      // Simple Check
      if (!d_key->pkey) return 0;

      switch (EVP_PKEY_type(d_key->pkey->type)) {

        // RSA Keys
        case EVP_PKEY_RSA: {

          // Checks we have the correct encryption algorithm
          if (enc_data->data[0] != LIBEC_ENC_ALG_RSA) goto err;

          // Allocates the Context for Public Key Operations
          if ((inner_ctx->pkey_ctx = EVP_PKEY_CTX_new(d_key->pkey, NULL)) == NULL) goto err;

          // Initializes the Encryption (only works with RSA)
          if (1 != EVP_PKEY_decrypt_init(inner_ctx->pkey_ctx)) goto err;

          // Gets the size of the final encryption
          if (EVP_PKEY_decrypt(inner_ctx->pkey_ctx,
                               NULL,
                               &ret->skey.data_size,
                               enc_data->data + LIBEC_ENCRYPTED_PREFIX_SIZE,
                               enc_data->length - LIBEC_ENCRYPTED_PREFIX_SIZE) <= 0) goto err;

          // Checks we have enough space
          if (ret->skey.data_size > sizeof(tmp_buf)) goto err;

          if (EVP_PKEY_decrypt(inner_ctx->pkey_ctx,
                               tmp_buf,
                               &ret->skey.data_size,
                               enc_data->data + LIBEC_ENCRYPTED_PREFIX_SIZE,
                               enc_data->length - LIBEC_ENCRYPTED_PREFIX_SIZE) <= 0) goto err;

          // Copy the recovered data
          memcpy(ret->skey.data, tmp_buf, ret->skey.data_size);

          // Success!

        } break;

        // EC Keys
        case EVP_PKEY_EC : {

          // This case is a bit more complex, because we need to generate another point
          // on the curve, then use the destination key (d_key) and the ephemeral key (d_eph)
          // to derive the encryption key that will be used to encrypt the message
          fprintf(stderr, "ERROR: Encrypting for an EC key is NOT Implemented!\n");
          goto err;

        } break;

        default : {
          // ERROR
          goto err;
        }
      }

    } break;

    case LIBEC_KEY_TYPE_SYMMETRIC : {

      // Initializes the decryption
      if (NULL == _decrypt_init_sym(&inner_ctx,
                                    enc_data->data,
                                    enc_data->length,
                                    d_key->skey.data,
                                    d_key->skey.data_size)) goto err;

      // Checks that the size of the encrypted ciphertext is not bigger than
      // the destination key holder (ret->skey.data)
      if (sizeof(ret->skey.data) <
          inner_ctx->dec_data + inner_ctx->dec_data_size - inner_ctx->dec_data_next) goto err;

      // Decrypts the key data
      if (1 != EVP_DecryptUpdate(inner_ctx->cipher_ctx,
                                 ret->skey.data,
                                 &outd,
                                 inner_ctx->dec_data_next,
                                 inner_ctx->dec_data
                                   + inner_ctx->dec_data_size
                                   - inner_ctx->dec_data_next)) goto err;
      ret->skey.data_size = outd;

      // Finalizes the Decryption
      if (1 != _decrypt_final_sym(ret->skey.data
                                    + ret->skey.data_size,
                                  &outl,
                                  inner_ctx)) goto err;
      if (outl > 0) ret->skey.data_size += outl;

      // All Done
    } break;

    default : {
      // Not Recognize Key Type
      goto err;
    } break;
  }

  // Sets the output key type
  ret->type = LIBEC_KEY_TYPE_SYMMETRIC;

  // Sets the output parameter
  if (out) *out = ret;

  // Free resources
  if (!(ctx && *ctx)) {
    if (inner_ctx) LIBEC_CTX_free(inner_ctx);
  }

  // Success
  return ret;

err:

  // Free the Crypto CTX
  if (!(ctx && *ctx)) {
    if (inner_ctx) LIBEC_CTX_free(inner_ctx);
    if (ctx) *ctx = NULL;
  }

  // Free (if allocated) output structure
  if (!(out && *out)) {
    if (ret) LIBEC_KEY_free(ret);
    if (out) *out = NULL;
  }

  // Reports the error
  return NULL;
}

// ==================
// Exported Functions
// ==================

void LIBEC_cleanup() {
	ERR_free_strings();
	X509V3_EXT_cleanup();
	OBJ_cleanup();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

void LIBEC_init() {

	int i = 0;

	// Used to initialize config and dynamic ENGINE config
	// OPENSSL_config(NULL);

	X509V3_add_standard_extensions();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();

	ERR_load_ERR_strings();
	ERR_load_crypto_strings();

	lock_cs=OPENSSL_malloc((size_t) (((size_t)CRYPTO_num_locks()) *
			sizeof(pthread_mutex_t)));

	lock_count=OPENSSL_malloc(((size_t) (CRYPTO_num_locks()) *
			sizeof(long)));

	for (i=0; i<CRYPTO_num_locks(); i++) {
		lock_count[i]=0;
		pthread_mutex_init(&(lock_cs[i]),NULL);
	}

	CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
	CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);


#ifdef LIBEC_ENABLE_ENGINE
#ifndef OPENSSL_NO_ENGINE              // OPENSSL_NO_ENGINE //

	// Initializes the Engine SubSystem and loads the built-in
	// RDRAND engine (supposedly has much better performances for
	// random number generations as it uses (OpenSSL 1.0.1+) the
	// 3rd generation Core i5 or i7 processors Secure Key Technology
	// https://software.intel.com/en-us/blogs/2012/05/14/what-is-intelr-secure-key-technology
	// https://software.intel.com/en-us/articles/performance-impact-of-intel-secure-key-on-openssl
	ENGINE_load_builtin_engines();
	ENGINE_load_rdrand(); // <<--- This is called in the previous call, but needs to be
	                      //       explicitly invoked in future versions of OpenSSL
	// OPENSSL_cpuid_setup(); <<--- Called in ENGINE_load_builtin_engines()

#ifndef OPENSSL_NO_STATIC_ENGINE       // OPENSSL_NO_STATIC_ENGINE //

// Loading the rdrand engine makes sense only on Intel platforms
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86) || defined(__ia64) || defined(__itanium__) || defined(_M_IA64) // Intel Processors

	int rv = -1;

	// Gets the reference to the RDRAND engine
	if ((rand_eng = ENGINE_by_id("rdrand")) != 0) {

		// Here we have the engine reference, we need to initialize it
		if ((rv = ENGINE_init(rand_eng)) == 0) {
			// Let's report the error and exit (it should not happen we
			// cannot initialize the RDRAND engine)
			ERR_print_errors_fp(stderr);
			exit(1);
		}

		// Let's now register the RDRAND engine as the default RND gen
		if ((rv = ENGINE_set_default(rand_eng, ENGINE_METHOD_RAND)) == 0) {
			// Prints the Error and exists (non-recoverable error)
			ERR_print_errors_fp(stderr);
			exit(1);
		}
	}

	ERR_print_errors_fp(stderr);

#endif // Intel Processors //

#endif // OPENSSL_NO_STATIC_ENGINE //
#endif // OPENSSL_NO_ENGINE        //
#endif // LIBEC_ENABLE_ENGINE       //
}



int LIBEC_data_cmp(const unsigned char *h1, size_t h1_size,
                         const unsigned char *h2, size_t h2_size) {

	// Checks the different parameters
	if (!h1 || !h1_size || !h2 || !h2_size ||
			h1_size != h2_size || memcmp(h1, h2, h1_size)) return 0;

	// Success, they are identical
	return 1;
}


// =========================
// Crypto Context Management
// =========================

LIBEC_CTX * LIBEC_CTX_new() {

	LIBEC_CTX * ret = NULL;

	// Allocates the memory
	if ((ret = OPENSSL_malloc(sizeof(LIBEC_CTX))) == NULL) return NULL;

	// Zeroizes the memory
	memset(ret, 0, sizeof(LIBEC_CTX));

	// Initializes the Context for HMAC(s)
	if ((ret->hmac_ctx = HMAC_CTX_new()) == NULL) goto err;
	HMAC_CTX_init(ret->hmac_ctx);

	// Initializes the context for Digests
	if ((ret->md_ctx = EVP_MD_CTX_new()) == NULL) goto err;
	EVP_MD_CTX_init(ret->md_ctx);

	// Initializes the context for Encryption
  if ((ret->cipher_ctx = EVP_CIPHER_CTX_new()) == NULL) goto err;
  EVP_CIPHER_CTX_init(ret->cipher_ctx);

	// All Done
	return ret;

err:

	// Cleanup Memory
  if (ret) LIBEC_CTX_free(ret);

	// Report the Error
	return NULL;
}

int LIBEC_CTX_cleanup(LIBEC_CTX * ctx) {

	// Input Checks
	if (!ctx || !ctx->hmac_ctx || !ctx->md_ctx) return 0;

	// Cleanup the HMAC ctx
	if (ctx->hmac_ctx) HMAC_CTX_cleanup(ctx->hmac_ctx);

	// Cleanup the EVP_MD ctx
	if (ctx->md_ctx) EVP_MD_CTX_cleanup(ctx->md_ctx);

	// Cleanup the Encryption ctx
	if (ctx->cipher_ctx) EVP_CIPHER_CTX_cleanup(ctx->cipher_ctx);

  // Cleanup Key Digest
	if (ctx->k_enc.data) OPENSSL_free(ctx->k_enc.data);
	ctx->k_enc.data = NULL;
	ctx->k_enc.length = 0;

  // Cleanup the Encryption Key
  if (ctx->enc_data) OPENSSL_free(ctx->enc_data);
  ctx->enc_data      = 0;
  ctx->enc_data_size = 0;

  ctx->enc_data_iv   = 0;
  ctx->enc_data_tag  = 0;

  ctx->enc_data_next = 0;
  ctx->enc_data_end  = 0;

  ctx->dec_data = NULL;
  ctx->dec_data_next = NULL;
  ctx->dec_data_size = 0;

  // Cleanup the Public Key ctx
  if (ctx->pkey_ctx) {
    EVP_PKEY_CTX_free(ctx->pkey_ctx);
    ctx->pkey_ctx = NULL;
  }

	// Success
	return 1;
}

void LIBEC_CTX_free(LIBEC_CTX * ctx) {

	// Input Check
	if (!ctx) return;

	// Cleanup
	LIBEC_CTX_cleanup(ctx);

	// Free the contexts
	if (ctx->hmac_ctx) HMAC_CTX_free(ctx->hmac_ctx);

	if (ctx->md_ctx) EVP_MD_CTX_free(ctx->md_ctx);

  if (ctx->cipher_ctx) EVP_CIPHER_CTX_free(ctx->cipher_ctx);

  if (ctx->pkey_ctx) EVP_PKEY_CTX_free(ctx->pkey_ctx);

  // Free encryption key and data
  if (ctx->enc_data) OPENSSL_free(ctx->enc_data);

  // Cleanup the encrypted key data (from encryption ops)
  ASN1_OCTET_STRING_cleanup(&ctx->k_enc);

	// Free the CTX memory
	OPENSSL_free(ctx);

	// All Done
	return;
}

// ========================
// Crypto Digest Management
// ========================

void LIBEC_DIGEST_cleanup(LIBEC_DIGEST * x) {

  // Input Check
  if (!x) return;

  // Free Memory (if any)
  if (x->data) OPENSSL_free(x->data);
  x->data = NULL;
  x->length = 0;

  // All Done
  return;
}

LIBEC_DIGEST * LIBEC_DIGEST_new(LIBEC_DIGEST     ** dgst,
		                                        LIBEC_DIGEST_ALG    alg,
		                                        const unsigned char     * data,
											                      size_t                    size) {

	LIBEC_DIGEST * ret = NULL;
		// Container for the final return structure

	unsigned char * buf = NULL;
	unsigned int buf_len = 0;
		// Digest Value Buffer

  const EVP_MD * md = NULL;
    // OpenSSL MD

	// Input Check
	if (!data || !size) return NULL;

	// Setup the Container's pointers
	if (dgst && *dgst) {
		// Use the passed container
		ret = *dgst;
		// Cleanup the Key
		LIBEC_DIGEST_cleanup(ret);
	} else {
		// Allocates the memory for the container
		if ((ret = LIBEC_DIGEST_new_null()) == NULL) return NULL;
	}

	// Gets the algorithm
	if (!alg) alg = LIBEC_DIGEST_ALG_DEFAULT;

	// Transforms the Algorithm identifier to the EVP_MD from OpenSSL
	if ((md = _get_evp_md(LIBEC_DIGEST_ALG_DEFAULT)) == NULL) goto err;

	// Allocates the Buffer Memory
	if ((buf = OPENSSL_malloc(EVP_MD_size(md) + LIBEC_DIGEST_PREFIX_SIZE)) == NULL) goto err;

	// Calculates the digest and saves it in the allocated buffer
	if (1 != EVP_Digest(data, size, buf + LIBEC_DIGEST_PREFIX_SIZE, &buf_len, md, NULL)) goto err;

	// Sets the algorithm identifier
	switch(EVP_MD_type(md)) {
		case NID_sha256: {
			buf[0] = LIBEC_DIGEST_ALG_SHA256 &
					 LIBEC_DIGEST_ALG_MASK;
		} break;

		case NID_sha384: {
			buf[0] = LIBEC_DIGEST_ALG_SHA384 &
					 LIBEC_DIGEST_ALG_MASK;
		} break;

		case NID_sha512: {
			buf[0] = LIBEC_DIGEST_ALG_SHA512 &
					 LIBEC_DIGEST_ALG_MASK;
		} break;

		default:
			// Error if not supported algor
			goto err;
	}

	// Now let's transfer the buffer to the output string
	ret->data = buf;
	ret->length = buf_len + LIBEC_DIGEST_PREFIX_SIZE;

	// Sets the output parameter
	if (dgst) *dgst = ret;

	// All Done
	return ret;

err:

	if (!(dgst && *dgst)) {
		// Frees allocated memory
		if (ret) LIBEC_DIGEST_free(ret);
		// Resets the output parameter
		*dgst = NULL;
	}

	// Returns the error
	return NULL;
}

int LIBEC_DIGEST_encode(unsigned char            ** data,
                              size_t                    * size,
                              const LIBEC_DIGEST  * dgst) {
	int i = 0;
	unsigned char * tmp = 0;

	LIBEC_DIGEST * tmp_dgst = (LIBEC_DIGEST *)dgst;

	// Input Checks
	if (!data || !size || !dgst) return 0;

	// Gets the encoded size
	if ((i = i2d_ASN1_OCTET_STRING(tmp_dgst, NULL)) < 1) return 0;

	// Allocates the right space
	if ((*data = OPENSSL_malloc(i)) == NULL) return 0;

	// Encodes the value
	tmp = *data;
	if ((i = i2d_ASN1_OCTET_STRING(tmp_dgst, &tmp)) <= 0) {
		OPENSSL_free(*data);
		return 0;
	}

	// Sets the output value for the size
	*size = i;

	// Returns success
	return 1;
}

LIBEC_DIGEST * LIBEC_DIGEST_decode(LIBEC_DIGEST  ** dgst,
                                               const unsigned char ** next,
											                         const unsigned char  * data,
                                               size_t                 size) {

	LIBEC_DIGEST * ret = NULL;
	const unsigned char *p = data;

	// Input Check
	if (!data && !size) return NULL;

	// Decode the Structure
	if ((ret = d2i_ASN1_OCTET_STRING(dgst, &p, size)) == NULL) return NULL;

	// Adjust the output parameters
	if (next) *next = p;

	// Success
	return ret;
}

LIBEC_DIGEST_ALG LIBEC_DIGEST_algor(const LIBEC_DIGEST *dgst) {

	uint8_t val = 0;

	// Input Checks
	if (!dgst || !dgst->data || dgst->length < 1)
		return LIBEC_DIGEST_ALG_UNKNOWN;

	// Gets the stored algor
	val = dgst->data[0] & LIBEC_DIGEST_ALG_MASK;

	// Checks we have a valid value
	switch (val) {
		case LIBEC_DIGEST_ALG_SHA256:
		case LIBEC_DIGEST_ALG_SHA384:
		case LIBEC_DIGEST_ALG_SHA512:
			break;

		default:
			return LIBEC_DIGEST_ALG_UNKNOWN;
			break;
	}

	// All Ok
	return val;
}

size_t LIBEC_DIGEST_value(const unsigned char      ** data,
                                const LIBEC_DIGEST  * dgst) {

	size_t ret = 0;

	// Input Check
	if (!dgst) return 0;

	// Sets the output pointer
	if (data) *data = dgst->data + LIBEC_DIGEST_PREFIX_SIZE;

	// Returns the size
	return (size_t) dgst->length - LIBEC_DIGEST_PREFIX_SIZE;
}

// =====================
// Crypto Key Management
// =====================

LIBEC_KEY * LIBEC_KEY_new() {

	LIBEC_KEY * ret;

	// Allocates memory
	if ((ret = OPENSSL_malloc(sizeof(LIBEC_KEY))) == NULL) return NULL;

	// Initialization (Asymmetric)
	ret->pkey = NULL;

  // Initialization (Symmetric)
	ret->skey.data_size = 0;

	// All Done
	return ret;
}

LIBEC_KEY * LIBEC_KEY_gen_ec(LIBEC_KEY      ** key,
		                                 LIBEC_EC_CURVE    curve) {

	LIBEC_KEY * ret = NULL;
		// Return data structure

	// Checks allowed curves
	switch(curve) {

		// All Accepted Values
		case LIBEC_EC_CURVE_ANY:
		case LIBEC_EC_CURVE_GOOD:
		case LIBEC_EC_CURVE_BETTER:
		case LIBEC_EC_CURVE_BEST:
			break;

		// Anything else should fail
		default:
			return 0;
			break;
	}

	// Setup the Container's pointers
	if (key && *key) {
		// Use the passed container
		ret = *key;
		// Cleanup the Key
		LIBEC_KEY_cleanup(ret);
	} else {
		// Allocates the memory for the container
		if ((ret = LIBEC_KEY_new()) == NULL) return NULL;
	}

	// Sets the type
	ret->type = LIBEC_KEY_TYPE_ASYMMETRIC;

	// Generates the new key
	if ((ret->pkey = _gen_ec(curve)) == NULL) {
		if (!(key && *key)) LIBEC_KEY_free(ret);
		return NULL;
	}

	// Sets the output parameter
	if (key) *key = ret;

	// All Done
	return ret;
}

LIBEC_KEY * LIBEC_KEY_gen_rsa(LIBEC_KEY      ** key,
                                          LIBEC_RSA_SIZE    bits) {

	LIBEC_KEY * ret = NULL;
		// Return data structure

	// Checks allowed strengths
	switch(bits) {

		// All Accepted value
		case LIBEC_RSA_SIZE_ANY:
		case LIBEC_RSA_SIZE_GOOD:
		case LIBEC_RSA_SIZE_BETTER:
		case LIBEC_RSA_SIZE_BEST:
			break;

		// Everything else should fail
		default:
			return NULL;
			break;
	}

	// Setup the Container's pointers
	if (key && *key) {
		// Use the passed container
		ret = *key;
		// Cleanup the Key
		LIBEC_KEY_cleanup(ret);
	} else {
		// Allocates the memory for the container
		if ((ret = LIBEC_KEY_new()) == NULL) return NULL;
	}

	// Sets the type
	ret->type = LIBEC_KEY_TYPE_ASYMMETRIC;

	// Generates the new key
	if ((ret->pkey = _gen_rsa(bits)) == NULL) {
		if (!(key && *key)) LIBEC_KEY_free(ret);
		return NULL;
	}

	// Sets the output parameter
	if (key) *key = ret;

	// All Done
	return ret;
}

LIBEC_KEY * LIBEC_KEY_gen_aes(LIBEC_KEY      ** key,
                                          LIBEC_AES_SIZE    bits) {

	LIBEC_KEY * ret = NULL;
		// Return data structure

	if (bits == LIBEC_AES_SIZE_ANY) bits = LIBEC_AES_SIZE_GOOD;
	else if ((int)bits > EVP_MAX_KEY_LENGTH * 8) bits = EVP_MAX_KEY_LENGTH;

	// Checks allowed strengths
	switch(bits) {
		case LIBEC_AES_SIZE_GOOD:
		case LIBEC_AES_SIZE_BETTER:
		case LIBEC_AES_SIZE_BEST:
			break;

		default:
			return 0;
			break;
	}

  // Transforms it in bytes
  bits /= 8;

	// Setup the Container's pointers
	if (key && *key) {
		// Use the passed container
		ret = *key;
		// Cleanup the key internals
		LIBEC_KEY_cleanup(ret);
	} else {
		// Allocates the memory for the container
		if ((ret = LIBEC_KEY_new()) == NULL) return NULL;
	}

	// Checks it is a good size
	if (bits > sizeof(ret->skey.data)) goto err;

	// Sets the type
	ret->type = LIBEC_KEY_TYPE_SYMMETRIC;

	// Generates the random bits
	if (!RAND_bytes(ret->skey.data, bits)) goto err;

	// Fixes the key data size
	ret->skey.data_size = bits;

	// Sets the output parameter
	if (key) *key = ret;

	// All Done
	return ret;

err:

	// Resets the output parameters
	if (!(key && *key)) {
		// Free used memory
		if (ret) LIBEC_KEY_free(ret);
		*key = NULL;
	}

	// Returns the error
	return NULL;
}

int LIBEC_KEY_encode_public(unsigned char        ** data,
                                  size_t                * data_size,
                                  const LIBEC_KEY * key) {

	// Input Check
	if (!data || !data_size || !key || !key->pkey) return 0;

	// Let's just invoke the right call
	return _pubkey_encode(key->pkey, data, data_size);
}

int LIBEC_KEY_encode_private(unsigned char        ** data,
                                   size_t                * data_size,
                                   const LIBEC_KEY * key) {

	// Input Check
	if (!data || !data_size || !key) return 0;

	// Separate the behavior for symmetric and asymmetric keys
	switch (key->type) {
	case LIBEC_KEY_TYPE_ASYMMETRIC: {
			return _privkey_encode(key->pkey, data, data_size);
		} break;

	case LIBEC_KEY_TYPE_SYMMETRIC: {
			return _privkey_encode_sym(data, data_size, key->skey.data, key->skey.data_size);
		} break;

	default:
		// ERROR
		return 0;
	}

	return 1;
}

LIBEC_KEY * LIBEC_KEY_decode_public(LIBEC_KEY     ** key,
                                                const unsigned char  * data,
                                                size_t                 data_size) {

	LIBEC_KEY * ret = NULL;
	EVP_PKEY * pkey = NULL;

	// Input Check
	if (!data || !data_size) return NULL;

	// Setup the Container's pointers
	if (key && *key) {
		// Use the passed container
		ret = *key;
		// Cleanup the key internals
		LIBEC_KEY_cleanup(ret);
	} else {
		// Allocates the memory for the container
		if ((ret = LIBEC_KEY_new()) == NULL) {
			// Here we had an error
			goto err;
		}
	}

	// Now we can build the right object and return it
	ret->type = LIBEC_KEY_TYPE_ASYMMETRIC;

	// Parses the encoded public key
	if ((pkey = _pubkey_decode(&ret->pkey, data, data_size)) == NULL) goto err;

	// Assigns the value to the output parameter
	if (key) *key = ret;

	// Success
	return ret;

err:

	// Free Memory
	if (pkey) EVP_PKEY_free(pkey);

	// Fix output parameters
	if (!(key && *key)) {
		if (ret) LIBEC_KEY_free(ret);
		*key = NULL;
	}

	// Report the error
	return NULL;
}

LIBEC_KEY * LIBEC_KEY_decode_private(LIBEC_KEY      ** key,
                                                 LIBEC_KEY_TYPE    type,
                                                 const unsigned char   * data,
                                                 size_t                  data_size) {

	LIBEC_KEY * ret = NULL;
	EVP_PKEY * pkey = NULL;

	// Input Check
	if (!data || !data_size) return NULL;

	// Setup the Container's pointers
	if (key && *key) {
		// Use the passed container
		ret = *key;
		// Cleanup the key internals
		LIBEC_KEY_cleanup(ret);
	} else {
		// Allocates the memory for the container
		if ((ret = LIBEC_KEY_new()) == NULL) {
			// Here we had an error
			return NULL;
		}
	}

	switch (type) {

		case LIBEC_KEY_TYPE_ASYMMETRIC: {

			// Sets the Key Type
			ret->type = LIBEC_KEY_TYPE_ASYMMETRIC;

			// Parses the asymmetric key
			if ((pkey = _privkey_decode(data, data_size)) == NULL) goto err;
			ret->pkey = pkey;

		} break;

		case LIBEC_KEY_TYPE_SYMMETRIC : {

			// Sets the Key Type
			ret->type = LIBEC_KEY_TYPE_SYMMETRIC;

			// Parses the symmetric key
			if (1 != _privkey_decode_sym(ret->skey.data, &ret->skey.data_size, data, data_size)) goto err;

		} break;

		default:
			// Nothing to do
			break;
	}

	// Assigns the value to the output parameter
	if (key) *key = ret;

	// Returns a valid structure if the type was recognized,
	// otherwise it returns the NULL value (var initialization)
	return ret;

err:

	// Free used Memory
	if (pkey) EVP_PKEY_free(pkey);

	if (!(key && *key)) {
		// Free used Memory
		if (ret) LIBEC_KEY_free(ret);
		// Resets the output parameters
		if (key) *key = NULL;
	}

	// Returns the error condition
	return NULL;
}

LIBEC_DIGEST * LIBEC_KEY_identifier(LIBEC_DIGEST    ** dgst,
                                                const LIBEC_KEY  * key,
                                                LIBEC_DIGEST_ALG   dgst_alg) {

  LIBEC_DIGEST * ret = NULL;
		// Return container

	unsigned char *buf = NULL;
	size_t buf_size = 0;
		// Temporary container for the DER encoded public key
		// for the asymmetric case

	// Input Check
	if (!key) return NULL;

  // Gets the Key Material
	switch (key->type) {

		// Symmetric Key
		case LIBEC_KEY_TYPE_SYMMETRIC: {

			// Calculates the Digest over the symmetric key material
			if ((ret = LIBEC_DIGEST_new(dgst,
			                                  dgst_alg,
			                                  key->skey.data,
			                                  key->skey.data_size)) == NULL) goto err;
		} break;

		// Asymmetric Key
		case LIBEC_KEY_TYPE_ASYMMETRIC : {

			// Needs the Encoded version of the key first
			if (1 != LIBEC_KEY_encode_public(&buf, &buf_size, key)) goto err;

			// Calculates the Digest over the symmetric key material
			if ((ret = LIBEC_DIGEST_new(dgst,
										                    dgst_alg,
											                  buf,
											                  buf_size)) == NULL) goto err;

			// Free the allocated memory
			OPENSSL_free(buf);
			buf = NULL; // Safety
		} break;

		// Not Recognized Type
		default: {
			// Error
			goto err;
		} break;
	}

	// Fix the output parameter
	if (dgst) *dgst = ret;

	// All Done
	return ret;

err:

	// Free allocated memory
	if (buf) OPENSSL_free(buf);

	// Fix output parameter
	if (!(dgst && *dgst)) {
		if (ret) LIBEC_DIGEST_free(ret);
		*dgst = NULL;
	}

	// Returns the error
	return NULL;
}

void LIBEC_KEY_cleanup(LIBEC_KEY * key) {

	// Input Check
	if (!key) return;

	// Cleanup the Asymmetric key
	if (key->pkey) {

		// Cleanup the key data
		EVP_PKEY_free(key->pkey);

		// Resets the pointer
		key->pkey = NULL;
	}

	// Cleanup the Symmetric Key
	OPENSSL_cleanse(key->skey.data, key->skey.data_size);

	// Resets the Size
	key->skey.data_size = 0;

	// Cleanup type and context
	key->type = LIBEC_KEY_TYPE_UNKNOWN;

	// Success;
	return;
}

void LIBEC_KEY_free(LIBEC_KEY * key) {

	// Input Check
	if (!key) return;

	// Cleanup the Key structures
	LIBEC_KEY_cleanup(key);

	// Free the Memory
	OPENSSL_cleanse(key, sizeof(LIBEC_KEY));
	OPENSSL_free(key);

	// All Done
	return;
}

// =====================
// Signatures Management
// =====================

int LIBEC_SIGNATURE_encode(unsigned char               ** data,
                                 size_t                       * size,
                                 const LIBEC_SIGNATURE  * sig) {

	int i = 0;
	unsigned char * tmp = 0;

	// Input Checks
	if (!data || !size || !sig) return 0;

	// Gets the encoded size
	if ((i = i2d_LIBEC_SIGNATURE((LIBEC_SIGNATURE  *)sig, NULL)) < 1) return 0;

	// Allocates the right space
	if ((*data = OPENSSL_malloc(i)) == NULL) return 0;

	// Encodes the value
	tmp = *data;
	if ((i = i2d_LIBEC_SIGNATURE((LIBEC_SIGNATURE  *)sig, &tmp)) <= 0) {
		OPENSSL_free(*data);
		return 0;
	}

	// Sets the output value for the size
	*size = i;

	// Returns success
	return 1;

}

LIBEC_SIGNATURE * LIBEC_SIGNATURE_decode(LIBEC_SIGNATURE ** sig,
                                                     const unsigned char   ** next,
                                                     const unsigned char    * data,
                                                     size_t                   size) {

	LIBEC_SIGNATURE * ret = NULL;
	const unsigned char *p = data;

	// Input Check
	if (!data && !size) return NULL;

	// Decode the Structure
	if ((ret = d2i_LIBEC_SIGNATURE(sig, &p, size)) == NULL) return NULL;

	// Adjust the output parameters
	if (next) *next = p;

	// Success
	return ret;
}

int LIBEC_SIGNATURE_algor(LIBEC_ALGOR           * algor,
								LIBEC_DIGEST_ALG      * dgst,
								const LIBEC_SIGNATURE * sig) {

	// Input Check
	if (!sig || !sig->value || !sig->value->data || sig->value->length < 1)
		return 0;

	// Let's save the output parameters
	*algor = sig->value->data[0] & LIBEC_ALGOR_MASK;
	*dgst  = sig->value->data[0] & LIBEC_DIGEST_ALG_MASK;

	// Success
	return (uint8_t) sig->value->data[0];
}

size_t LIBEC_SIGNATURE_value(const unsigned char         ** data,
                                   const LIBEC_SIGNATURE  * sig) {

	size_t ret = 0;

	// Input Check
	if (!sig || !sig->value || !sig->value->data) return 0;

	// Sets the output pointer (after the prefix)
	if (data) *data = sig->value->data + LIBEC_SIGNATURE_PREFIX_SIZE;

	// Returns the size (minus the prefix len)
	return (size_t) sig->value->length - LIBEC_SIGNATURE_PREFIX_SIZE;
}

size_t LIBEC_SIGNATURE_identifier(const unsigned char        ** data,
                                        LIBEC_DIGEST_ALG      * dgst_alg,
                                        const LIBEC_SIGNATURE * sig) {

	// Input Check
	if (!sig || !sig->keyIdentifier) return 0;

  // Returns the values via the auxillary function
  return _get_identifier(data, dgst_alg, sig->keyIdentifier);
}

// ================================
// Signatures (Asymmetric AND HMAC)
// ================================

LIBEC_CTX * LIBEC_sign_init(LIBEC_CTX        ** ctx,
                                        const LIBEC_KEY   * key,
                                        LIBEC_DIGEST_ALG    dgst_alg,
                                        const unsigned char     * data,
                                        size_t                    data_size) {

	LIBEC_CTX * ret = NULL;
	  // Return Structure

	const EVP_MD * md = NULL;
	  // OpenSSL Message digest

	// Input Check
	if (!key) return NULL;

	// Sets the default digest to use
	if (!md) md = _get_evp_md(LIBEC_DIGEST_ALG_DEFAULT);

	// Creates the context
	if (ctx && *ctx) {
		// Gets the Pointer to already initialized structure
		// (can be useful to re-use without needed re-allocation
		ret = *ctx;
		// Cleanup the crypto context
		LIBEC_CTX_cleanup(ret);
	} else {
		// Let's make sure we have a good memory allocation
		if ((ret = LIBEC_CTX_new()) == NULL) {
			// If we can not allocate a new CTX, let's return NULL
			return NULL;
		}
	}

	// Sets the default if none was specified
	if (!dgst_alg) dgst_alg = LIBEC_DIGEST_ALG_DEFAULT;

	// Gets the EVP_MD for the corresponding digest algorithm
	if ((md = _get_evp_md(dgst_alg)) == NULL) goto err;

	// Different operations for Symmetric vs. Asymmetric
	switch (key->type) {

		// ASYMMETRIC signature
		case LIBEC_KEY_TYPE_ASYMMETRIC: {

			// Checks we have a pkey
			if (!key->pkey) goto err;

			// Initializes / Resets the Context
			EVP_MD_CTX_init(ret->md_ctx);

			// Initializes the Signature's MD algorithm
			EVP_SignInit_ex(ret->md_ctx, md, NULL);

			// Let's update the MD
			if (data && data_size && EVP_SignUpdate(ret->md_ctx, data, (int)data_size) != 1) {
				// Error, let's free and return Error
				goto err;
			}
		} break;

		// SYMMETRIC signature (HMAC)
		case LIBEC_KEY_TYPE_SYMMETRIC: {

			// Checks we have the symmetric key
			if (!key->skey.data_size) goto err;

		    // Initializes the HMAC_CTX structure
		    HMAC_CTX_init(ret->hmac_ctx);

		    // Initialize the Context
#if OPENSSL_VERSION_NUMBER < 0x0090899fL // OPENSSL VERSION < 0.9.9
		    HMAC_Init_ex(ret->hmac_ctx, ret, key->skey.data, (int)key->skey.data_size, md, (ENGINE *)NULL);
#else
		    if (!HMAC_Init_ex(ret->hmac_ctx, key->skey.data, (int)key->skey.data_size, md, (ENGINE *)NULL)) goto err;
#endif
		    // Updates the Context
		    if (data && data_size && HMAC_Update(ret->hmac_ctx, data, data_size) != 1) {
		    	// Error, let's free and return Error
		    	goto err;
		    }

		} break;

		default: {
			// Unknown key type
			goto err;
		} break;
	}

	// Memoizes the key
	ret->key = key;

	// Assigns the structure to the output param
	if (ctx) *ctx = ret;

	// Returns the Generated context
	return ret;

err:

	// Memory Cleanup and Output Params Fixes
	if (!(ctx && *ctx)) {
    // Cleanup Memory
		if (ret) LIBEC_CTX_free(ret);
    // Fixes the out parameter
		*ctx = NULL;
	}

	// Returns the Error
	return NULL;
}

int LIBEC_sign_update(LIBEC_CTX     * ctx,
                            const unsigned char * data,
                            size_t                data_size) {

	// Input Check
	if (!ctx || !ctx->key || !data || !data_size || data_size >= INT_MAX) return 0;

	// Updates the Digest
	switch (ctx->key->type) {

		// ASYMMETRIC signature
		case LIBEC_KEY_TYPE_ASYMMETRIC: {
			// Returns the EVP update return code (0 is returned in case of error)
			return EVP_SignUpdate(ctx->md_ctx, data, (int)data_size);
		} break;

		// SYMMETRIC signature
		case LIBEC_KEY_TYPE_SYMMETRIC: {
			// Returns the HMAC update return code (0 is returned in case of error)
			return HMAC_Update(ctx->hmac_ctx, data, data_size);
		} break;

		// UNRECOGNIZED signature
		default: {
			// Unknown Key Type
			return 0;
		}
	}

	// Error
	return 0;
}

LIBEC_SIGNATURE * LIBEC_sign_final(LIBEC_SIGNATURE ** sig,
                                               LIBEC_CTX        * ctx) {

	LIBEC_SIGNATURE * ret = NULL;
		// Return Data Structure

	LIBEC_DIGEST * key_id = NULL;
		// Key Identifier structure

	unsigned char * tmp = NULL;
	unsigned char * buf = NULL;
	int buf_len = 0;
		// Signature Length

	// Input Check
	if (!ctx || !ctx->key) return NULL;

	// Creates the context
	if (sig && *sig) {
		// Gets the Pointer to already initialized structure
		// (can be useful to re-use without needed re-allocation
		ret = *sig;
	} else {
		// Let's make sure we have a good memory allocation
		if ((ret = LIBEC_SIGNATURE_new()) == NULL) {
			// If we can not allocate a new CTX, let's return NULL
			return NULL;
		}
	}

	// Different Operations for Symmetric and Asymmetric Key Types
	switch (ctx->key->type) {

		// ASYMMETRIC signature
		case LIBEC_KEY_TYPE_ASYMMETRIC: {

		  // We need a good key
		  if (!ctx->key->pkey) goto err;

			// Gets the size of the signature
			if ((buf_len = EVP_PKEY_size(ctx->key->pkey)) <= 0) goto err;

			// Allocates the max number of bytes
			if ((buf = OPENSSL_malloc(buf_len +
									  LIBEC_SIGNATURE_PREFIX_SIZE)) == NULL) goto err;

			// Finalizes the Signature
			if (1 != EVP_SignFinal(ctx->md_ctx,
								   buf + LIBEC_DIGEST_PREFIX_SIZE,
								   (unsigned int *)&buf_len, ctx->key->pkey)) goto err;

			// Sets the Algorithm's Schema in the buffer's first byte (4 msb)
			switch (ctx->key->pkey->type) {

				// RSA
				case EVP_PKEY_RSA: {
						buf[0] = LIBEC_ALGOR_RSA;
					} break;

				// ECDSA
				case EVP_PKEY_EC: {
						buf[0] = LIBEC_ALGOR_ECDSA;
					} break;

				// NOT Supported Algorithm
				default: {
						goto err;
					} break;
			}

			// Sets the hashing algorithm used in the buffer's first byte (4 lsb)
			switch (EVP_MD_CTX_type(ctx->md_ctx)) {

				// SHA-256
				case NID_sha256: {
						buf[0] |= LIBEC_DIGEST_ALG_SHA256;
					} break;

				// SHA-384
				case NID_sha384: {
						buf[0] |= LIBEC_DIGEST_ALG_SHA384;
					} break;

				// SHA-512
				case NID_sha512: {
						buf[0] |= LIBEC_DIGEST_ALG_SHA512;
					} break;

				// NOT Supported Digest
				default: {
						goto err;
					} break;
			}
		} break;

		// SYMMETRIC signature
		case LIBEC_KEY_TYPE_SYMMETRIC : {

			// Gets the required buffer memory
			if ((buf_len = HMAC_size(ctx->hmac_ctx)) <= 0) goto err;

			// Symmetric Key Signature operations (HMAC)
			// Allocates the required memory
			if ((buf = OPENSSL_malloc(buf_len +
									  LIBEC_SIGNATURE_PREFIX_SIZE)) == NULL) goto err;

#if OPENSSL_VERSION_NUMBER < 0x0090900fL // OPENSSL VERSION < 0.9.9
		    HMAC_Final(ctx->hmac_ctx, buf, &len);
#else
		    // Now let's calculate the HMAC
		    if (1 != HMAC_Final(ctx->hmac_ctx, buf +
		    					LIBEC_SIGNATURE_PREFIX_SIZE,
								(unsigned int *)&buf_len)) goto err;
#endif

		    // Sets the Algorithm's Schema in the buffer's first byte (4 msb)
		    buf[0] = LIBEC_ALGOR_HMAC;

		    // Sets the first byte to carry the algorithm
		    switch (EVP_MD_type(ctx->hmac_ctx->md)) {

		    	// SHA-256
				case NID_sha256: {
						buf[0] |= LIBEC_DIGEST_ALG_SHA256;
					} break;

				// SHA-384
				case NID_sha384: {
						buf[0] |= LIBEC_DIGEST_ALG_SHA384;
					} break;

				// SHA-512
				case NID_sha512: {
						buf[0] |= LIBEC_DIGEST_ALG_SHA512;
					} break;

				// NOT Supported Case
				default: {
						goto err;
					} break;
			}

		} break;

		// UNKNOWN signature
		default : {
			// Non-Supported Key Type
			goto err;
		}
	}

	// Gets the identifier
	if (NULL == LIBEC_KEY_identifier(&(ret->keyIdentifier),
                                          ctx->key,
                                          buf[0] & LIBEC_DIGEST_ALG_MASK)) goto err;

  // Cleanup the context
  LIBEC_CTX_cleanup(ctx);

  // Free existing data (if any)
  if (!ret->value) ret->value = ASN1_OCTET_STRING_new();
  else if (ret->value->data) OPENSSL_free(ret->value->data);

  // Transfers ownership of the signature's value
  ret->value->length = buf_len + LIBEC_DIGEST_PREFIX_SIZE;
  ret->value->data = buf;
  buf = NULL; // Safety

	// Assigns the structure to the output param
	if (sig) *sig = ret;

	// Success
	return ret;

err:

	// Memory Cleanup
	LIBEC_CTX_cleanup(ctx);

	// Buffer Cleanup
	if (buf) OPENSSL_free(buf);

	// Output Parameters Fix
	if (!(sig && *sig)) {
		if (ret) LIBEC_SIGNATURE_free(ret);
		*sig = NULL;
	}

	// Return the Error
	return NULL;
}


LIBEC_SIGNATURE * LIBEC_sign(LIBEC_CTX        ** ctx,
                                         LIBEC_SIGNATURE  ** sig,
                                         const LIBEC_KEY   * key,
                                         LIBEC_DIGEST_ALG    dgst_alg,
                                         const unsigned char     * data,
                                         size_t                    data_size) {

	LIBEC_SIGNATURE * ret = NULL;
		// Return Structure

	LIBEC_CTX * inner_ctx = NULL;
		// Local Context Pointer

	// Input Check
	if (!ctx || !key) return NULL;

	// Checks the ctx parameter
	if (ctx && *ctx) {
		/// Gets the context from the parameter
		inner_ctx = *ctx;
		// Cleanup the context
		LIBEC_CTX_cleanup(inner_ctx);
	} else {
		// Let's make sure we have a good inner_ctx
		if ((inner_ctx = LIBEC_CTX_new()) == NULL) goto err;
	}

  // Initialize the Signature
  if (NULL == LIBEC_sign_init(&inner_ctx, key, dgst_alg, data, data_size))
    goto err;

  // Finalizes the signature
  if ((ret = LIBEC_sign_final(sig, inner_ctx)) == NULL) goto err;

  // In case no CTX was initially passed, we need to free the
  // associated memory. If, instead, we have ctx and it was null,
  // we shall make sure we deliver the pointer to the caller
  if (!(ctx && *ctx)) LIBEC_CTX_free(inner_ctx);
  else if (ctx) *ctx = inner_ctx;

  // Returns the result
	return ret;

err:

	// Frees memory only if it did not come from the caller
	if (!(sig && *sig)) {
		// Frees the memory
		if (ret) LIBEC_SIGNATURE_free(ret);
		// Fixes the output
		*sig = NULL;
	}

	if (!(ctx && *ctx)) {
		// Frees the memory
		if (inner_ctx) LIBEC_CTX_free(inner_ctx);
		// Fixes the output
		*ctx = NULL;
	}

	// Returns the error
	return NULL;
}

LIBEC_CTX * LIBEC_verify_init(LIBEC_CTX             ** ctx,
                                          const LIBEC_SIGNATURE  * sig,
                                          const LIBEC_KEY        * key,
                                          const unsigned char          * data,
                                          size_t                         data_size) {

	LIBEC_CTX * ret = NULL;
		// Return CTX

	LIBEC_DIGEST_ALG a_dgst = 0;
	LIBEC_ALGOR a_algor     = 0;
		// Signature's algorithms

  const EVP_MD * md = _get_evp_md(LIBEC_DIGEST_ALG_DEFAULT);
    // HMAC Message Digest

	// Input Check
	if (!sig || !key) return NULL;

	// Creates the context
	if (ctx && *ctx) {
		// Gets the Pointer to already initialized structure
		// (can be useful to re-use without needed re-allocation
		ret = *ctx;
		// Cleanup the context
		LIBEC_CTX_cleanup(ret);
	} else {
		// Let's make sure we have a good memory allocation
		if ((ret = LIBEC_CTX_new()) == NULL) {
			// If we can not allocate a new CTX, let's return NULL
			goto err;
		}
	}

	// Attaches a reference to the key and the signature
	ret->sig = sig;
	ret->key = key;

	// Gets the Hash Algor to use
	if (0 == LIBEC_SIGNATURE_algor(&a_algor, &a_dgst, sig)) goto err;

  switch (key->type) {

		// ASYMMETRIC signature
		case LIBEC_KEY_TYPE_ASYMMETRIC: {

			// Checks we have a pkey
			if (!key->pkey) goto err;

			// Initializes / Resets the Context
			EVP_MD_CTX_init(ret->md_ctx);

	    // Returns '1' if success
	    if (1 != EVP_VerifyInit_ex(ret->md_ctx, _get_evp_md(a_dgst), NULL)) goto err;

	    // Let's update the MD
	    if (data && data_size && EVP_VerifyUpdate(ret->md_ctx, data, (int)data_size) != 1) {
		    // Error, let's free and return Error
		    goto err;
	    }

		} break;

		// SYMMETRIC signature (HMAC)
		case LIBEC_KEY_TYPE_SYMMETRIC: {

			// Checks we have the symmetric key
			if (!key->skey.data_size) goto err;

	    // Initializes the HMAC_CTX structure
	    HMAC_CTX_init(ret->hmac_ctx);

	    // Initialize the Context
#if OPENSSL_VERSION_NUMBER < 0x0090899fL // OPENSSL VERSION < 0.9.9
	    HMAC_Init_ex(ret->hmac_ctx, ret, key->skey.data, (int)key->skey.data_size,
        _get_evp_md(a_dgst), (ENGINE *)NULL);
#else
	    if (!HMAC_Init_ex(ret->hmac_ctx, key->skey.data, (int)key->skey.data_size,
        _get_evp_md(a_dgst), (ENGINE *)NULL)) goto err;
#endif
	    // Updates the Context
	    if (data && data_size && HMAC_Update(ret->hmac_ctx, data, data_size) != 1) {
	    	// Error, let's free and return Error
	    	goto err;
	    }

		} break;

		default: {
			// Unknown key type
			goto err;
		} break;
	}

	// Assigns the structure to the output param
	if (ctx) *ctx = ret;

	// All Done
	return ret;

err:

	// Output Setup
	if (!(ctx && *ctx)) {
		// Fixes the output parameters
		*ctx = NULL;
		// Free Memory
		if (ret) LIBEC_CTX_free(ret);
	}

	// Returns Nothing
	return NULL;
}

int LIBEC_verify_update(LIBEC_CTX     * ctx,
                              const unsigned char * data,
                              size_t                data_size) {

	// Input Check
	if (!ctx || !ctx->md_ctx || !data || !data_size || data_size >= INT_MAX) return 0;

  switch (ctx->key->type) {

		// ASYMMETRIC signature
		case LIBEC_KEY_TYPE_ASYMMETRIC: {

      // Checks we have a good context
      if (!ctx->md_ctx) return 0;

    	// Updates the Digest
	    return EVP_VerifyUpdate(ctx->md_ctx, data, (int)data_size);

    } break;

    // SYMMETRIC signature (HMAC)
    case LIBEC_KEY_TYPE_SYMMETRIC : {

      // Checks we have a good context
      if (!ctx->hmac_ctx) return 0;

      // Updates the HMAC
      return HMAC_Update(ctx->hmac_ctx, data, (int)data_size);
    } break;

    // UNKNOWN signature
    default : {
      return 0;
    }
  }

}

int LIBEC_verify_final(LIBEC_CTX * ctx) {

	const unsigned char * tmp = NULL;
	unsigned int tmp_len = 0;
		// Signature Max Length

  unsigned char buf[EVP_MAX_MD_SIZE];
  unsigned int hmac_size = 0;
    // HMAC temp buffer

  int rc = 0;
    // Return Code

	// Input Check
	if (!ctx || !ctx->key || !ctx->sig) return 0;

	// Uses the correct type
	tmp_len = (int) LIBEC_SIGNATURE_value(&tmp, ctx->sig);

  switch (ctx->key->type) {

		// ASYMMETRIC signature
		case LIBEC_KEY_TYPE_ASYMMETRIC: {

      // Checks we have a good context
      if (!ctx->md_ctx) goto err;

	    // Finalizes the Signature Verify
	    if ((rc = EVP_VerifyFinal(ctx->md_ctx, tmp, tmp_len, ctx->key->pkey)) != 1) goto err;

    } break;


		// SYMMETRIC signature (HMAC)
		case LIBEC_KEY_TYPE_SYMMETRIC: {

			// Checks we have the symmetric key
			if (!ctx->key->skey.data_size) goto err;

      // Extracts the right size
      if ((hmac_size = (unsigned int) HMAC_size(ctx->hmac_ctx)) <= 0) goto err;

      // Finalizes the HMAC
      if (1 != HMAC_Final(ctx->hmac_ctx, buf, &hmac_size)) goto err;

      // Compares the signature with the calculated HMAC
      if (hmac_size != tmp_len || memcmp(buf, tmp, tmp_len)) goto err;

      // Success
      rc = 1;

    } break;

    // UNKNOWN signature
    default : {
      // Error Condition
      goto err;
    }
  }

  // Cleanup the Context
  LIBEC_CTX_cleanup(ctx);

  // Returns success
  return rc;

err:

  LIBEC_CTX_cleanup(ctx);

  return 0;
}

int LIBEC_verify(LIBEC_CTX             ** ctx,
                       const LIBEC_SIGNATURE  * sig,
                       const LIBEC_KEY        * key,
                       const unsigned char          * data,
                       size_t                         data_size) {

  int rc = 0;
    // Return Code

  LIBEC_CTX * ret = NULL;
    // Context Structure

  // Input Checks
  if (!sig || !key || !data || !data_size) return 0;

  // Initializes the Signature Verification
  if ((ret = LIBEC_verify_init(ctx, sig, key, data, data_size)) == NULL)
    return 0;

  // Finalizes the signature verification
  rc = LIBEC_verify_final(ret);

  // Free memory if the 'ctx' parameter was not set
  if (!ctx) LIBEC_CTX_free(ret);

  // All Done
  return rc;
}

// ================
// ECDH Combination
// ================

LIBEC_KEY * LIBEC_ecdh_derive(LIBEC_KEY       ** key,
                                          const LIBEC_KEY  * my,
                                          const LIBEC_KEY  * other) {

	LIBEC_KEY * ret = NULL;
		// Return data structure

	EVP_PKEY_CTX * ctx = NULL;
		// Key Derivation Context

	unsigned char buf[EVP_MAX_KEY_LENGTH];
	size_t buf_size = 0;

	// Input Check
	if (!my || !my->pkey || !other || !other->pkey) return NULL;

	// Checks we have the right types
	if (my->pkey->type != EVP_PKEY_EC || other->pkey->type != EVP_PKEY_EC) return NULL;

	// Creates the context
	if (key && *key) {
		// Gets the Pointer to already initialized structure
		// (can be useful to re-use without needed re-allocation
		ret = *key;
		// Cleanup the context
		LIBEC_KEY_cleanup(ret);
	} else {
		// Let's make sure we have a good memory allocation
		if ((ret = LIBEC_KEY_new()) == NULL) {
			// If we can not allocate a new CTX, let's return NULL
			return NULL;
		}
		// Assigns the structure to the output param
		if (key) *key = ret;
	}

	// Sets the Key Details
	ret->type = LIBEC_KEY_TYPE_SYMMETRIC;

	// Creates a new context for key derivation
	if ((ctx = EVP_PKEY_CTX_new(my->pkey, NULL)) != NULL) {
		// Initializes the key derivation
		if (1 == EVP_PKEY_derive_init(ctx)) {
			// Gets the Size of the to-be-derived key
			if (1 == EVP_PKEY_derive_set_peer(ctx, other->pkey)) {
				// Gets the size of the required memory
				if (1 == EVP_PKEY_derive(ctx, NULL, &buf_size)) {
          // Derive the symmetric key
          if (1 == EVP_PKEY_derive(ctx, buf, &buf_size)) {
            // Use SHA-512 to generate enough bits for any Symmetric key
            if (1 == EVP_Digest(buf, buf_size,                     // IN Data
                            ret->skey.data, (unsigned int *)&ret->skey.data_size,  // OUT Data
                            EVP_sha512(), NULL)) {                 // HOW Data
              // All Ok
              if (ctx) EVP_PKEY_CTX_free(ctx);
              return ret;
            }
          }
				}
			}
		}
	}

	// Free the allocated memory
	if (ctx) EVP_PKEY_CTX_free(ctx);

	// Fixes the output parameters
	if (!(key && *key)) {
		if (ret) LIBEC_KEY_free(ret);
		*key = NULL;
	}

	// Error Condition
	return NULL;
}


// ====================================================
// Encryption and Decryption (Asymmetric and Symmetric)
// ====================================================

size_t LIBEC_ENC_ALG_sym_key_size(LIBEC_ENC_ALG alg) {

  switch (alg & LIBEC_ENC_ALG_MASK) {

    case LIBEC_ENC_ALG_AES_128 : {
      return 16;
    } break;

    case LIBEC_ENC_ALG_AES_192 : {
      return 24;
    } break;

    case LIBEC_ENC_ALG_AES_256 : {
      return 32;
    } break;

    default : {
      return 0;
    }
  }

  // No Symmetric Algor Found, let's return '0'
  return 0;
}

void LIBEC_ENCRYPTED_cleanup(LIBEC_ENCRYPTED * enc) {

  // Input Checks
  if (!enc) return;

  // Clears the Encryption Key Field
  if (enc->encryptionKey) ASN1_STRING_set0(enc->encryptionKey, NULL, 0);
  else enc->encryptionKey = ASN1_OCTET_STRING_new();

  // Clears the Key Identifier
  if (enc->keyIdentifier) ASN1_STRING_set0(enc->encryptionKey, NULL, 0);
  else enc->keyIdentifier = ASN1_OCTET_STRING_new();

  // Clears the Value
  if (enc->value) ASN1_STRING_set0(enc->value, NULL, 0);
  else enc->value = ASN1_OCTET_STRING_new();

  // All Done
  return;
}

int LIBEC_ENCRYPTED_encode(unsigned char               ** data,
								                 size_t                       * size,
								                 const LIBEC_ENCRYPTED  * enc) {

	int i = 0;
	unsigned char * tmp = 0;

	// Input Checks
	if (!data || !size || !enc) return 0;

	// Gets the encoded size
	if ((i = i2d_LIBEC_ENCRYPTED((LIBEC_ENCRYPTED  *)enc, NULL)) < 1) return 0;

	// Allocates the right space
	if ((*data = OPENSSL_malloc(i)) == NULL) return 0;

	// Encodes the value
	tmp = *data;
	if ((i = i2d_LIBEC_ENCRYPTED((LIBEC_ENCRYPTED  *)enc, &tmp)) <= 0) {
		OPENSSL_free(*data);
		return 0;
	}

	// Sets the output value for the size
	*size = i;

	// Returns success
	return 1;
}

LIBEC_ENCRYPTED * LIBEC_ENCRYPTED_decode(LIBEC_ENCRYPTED ** enc,
													                           const unsigned char   ** next,
													                           const unsigned char    * data,
													                           size_t                   size) {

	LIBEC_ENCRYPTED * ret = NULL;
	const unsigned char *p = data;

	// Input Check
	if (!data && !size) return NULL;

	// Decode the Structure
	if ((ret = d2i_LIBEC_ENCRYPTED(enc, &p, size)) == NULL) return NULL;

	// Adjust the output parameters
	if (next) *next = p;

	// Success
	return ret;
}

int LIBEC_ENCRYPTED_algor(LIBEC_ENC_ALG         * algor,
								                LIBEC_ENC_MODE        * mode,
								                const LIBEC_ENCRYPTED * enc) {

	// Input Check
	if (!enc || !enc->value || !enc->value->data || enc->value->length < 1)
		return 0;

	// Let's save the output parameters
	*algor = enc->value->data[0] & LIBEC_ENC_ALG_MASK;
	*mode  = enc->value->data[0] & LIBEC_ENC_MODE_MASK;

	// Success, returns the combined algorithm identifier
	return (uint8_t) enc->value->data[0];
}

size_t LIBEC_ENCRYPTED_value(const unsigned char         ** data,
								                   const LIBEC_ENCRYPTED  * enc) {
	size_t ret = 0;

	// Input Check
	if (!enc || !enc->value || !enc->value->data) return 0;

	// Sets the output pointer (after the prefix)
	if (data) *data = enc->value->data + LIBEC_ENCRYPTED_PREFIX_SIZE;

	// Returns the size (minus the prefix len)
	return (size_t) enc->value->length - LIBEC_ENCRYPTED_PREFIX_SIZE;
}

size_t LIBEC_ENCRYPTED_identifier(const unsigned char        ** data,
                                        LIBEC_DIGEST_ALG      * dgst_alg,
                                        const LIBEC_ENCRYPTED * enc) {

	// Input Check
	if (!enc || !enc->keyIdentifier) return 0;

	// Returns the values via the auxillary function
	return _get_identifier(data, dgst_alg, enc->keyIdentifier);
}

LIBEC_CTX * LIBEC_encrypt_init(LIBEC_CTX      ** ctx,
										                       const LIBEC_KEY * d_key,
                                           LIBEC_ENC_ALG     algor,
										                       LIBEC_ENC_MODE    mode,
										                       const unsigned char   * data,
										                       size_t                  data_size) {

  LIBEC_CTX * ret = NULL;
    // Return Structure

  const EVP_CIPHER * cipher = NULL;
    // HMAC Message Digest

  unsigned char * enc_key = NULL;
  unsigned char * tag_pnt = NULL;
  size_t enc_key_size = 0;
    // Local containers for key and iv

  ASN1_OCTET_STRING * o_pnt = NULL;
    // Encrypted container

  unsigned char * enc_key_data = NULL;
  size_t enc_key_data_size = 0;
    // Container for the encrypted data

  int outl = 0;
    // Encrypted Data Size

	// Input Check
	if (!d_key) return NULL;

	// Creates the context
	if (ctx && *ctx) {
		// Gets the Pointer to already initialized structure
		// (can be useful to re-use without needed re-allocation
		ret = *ctx;
		// Cleanup the context
		LIBEC_CTX_cleanup(ret);
	} else {
		// Let's make sure we have a good memory allocation
		if ((ret = LIBEC_CTX_new()) == NULL) {
			// If we can not allocate a new CTX, let's return NULL
			goto err;
		}
	}

	// Encrypts the Key
  if (NULL == _encrypt_key(&o_pnt, &enc_key, &enc_key_size, d_key, algor, mode)) goto err;

  // Initializes the data encryption
  if (NULL == _encrypt_init_sym(&ret, algor, mode, enc_key, enc_key_size)) goto err;

  // If there is data to be encrypted, let's encrypt it
  if (data && data_size) {

    // Encrypts the Data to the output buffer
    if (1 != EVP_EncryptUpdate(ret->cipher_ctx,
                               ret->enc_data + ret->enc_data_next,
                               &outl,
                               data,
                               data_size)) goto err;

    // Updates the size of the written data
    ret->enc_data_next += outl;
  }

  // Saves a reference to the recipient's key
  ret->key = d_key;
  ret->k_enc.data = o_pnt->data;
  ret->k_enc.length = o_pnt->length;

  // Free local resource
  o_pnt->data = NULL;
  o_pnt->length = 0;

  // Free the local pointer
  ASN1_OCTET_STRING_free(o_pnt);

  // Sets the output parameter
  if (ctx) *ctx = ret;

  // Make sure we do not leave keys in memory
  if (enc_key_size) OPENSSL_cleanse(enc_key, enc_key_size);
  OPENSSL_free(enc_key);

  // Success
  return ret;

err:

  // Resets the Context
  if (ret) LIBEC_CTX_cleanup(ret);
  if (o_pnt) ASN1_OCTET_STRING_free(o_pnt);

  // Free Unused memory
  if (!(ctx && *ctx)) {
    if (ret) LIBEC_CTX_free(ret);
  }

  if (enc_key) {
    // Clears the Memory
    if (enc_key_size) OPENSSL_cleanse(enc_key, enc_key_size);
    // Frees the memory
    OPENSSL_free(enc_key);
  }

  // Reports the Error
  return NULL;
}

int LIBEC_encrypt_update(LIBEC_CTX     * ctx,
				                       const unsigned char * data,
				                       size_t                data_size) {

  int outl;
    // Written Encrypted Data

  // Input Check
  if (!ctx || !ctx->enc_data || !ctx->enc_data_next) return 0;

  // Encrypt if we have data
  if (data && data_size) {

    // Encrypts the Data to the output buffer
    if (1 != EVP_EncryptUpdate(ctx->cipher_ctx,
                               NULL,
                               &outl,
                               data,
                               data_size)) return 0;

    // Realloc if more space is needed
    if (ctx->enc_data_size < ctx->enc_data_next + outl) {

      // Reserve enough memory to save the encrypted data
      ctx->enc_data = realloc(ctx->enc_data,
                              ctx->enc_data_size
                                + outl
                                + EVP_CIPHER_CTX_block_size(ctx->cipher_ctx));

      // Encrypts the Data to the output buffer
      if (1 != EVP_EncryptUpdate(ctx->cipher_ctx,
                                 ctx->enc_data + ctx->enc_data_next,
                                 &outl,
                                 data,
                                 data_size)) return 0;

      // Updates the size of the written data
      ctx->enc_data_next += outl;
    }
  }

  // Success
  return 1;
}

LIBEC_ENCRYPTED * LIBEC_encrypt_final(LIBEC_ENCRYPTED ** enc,
						                                      LIBEC_CTX        * ctx) {

  LIBEC_ENCRYPTED * ret = NULL;
    // Return Structure

  int outl = 0;
  size_t tag_size = 0;
    // Size of the AEAD Tag

  // Input Checks
  if (!ctx) return NULL;

  // Creates the context
  if (enc && *enc) {
    // Gets the Pointer to already initialized structure
    // (can be useful to re-use without needed re-allocation
    ret = *enc;
    // Cleanup the context
    LIBEC_ENCRYPTED_cleanup(ret);
  } else {
    // Let's make sure we have a good memory allocation
    if ((ret = LIBEC_ENCRYPTED_new()) == NULL) {
      // If we can not allocate a new CTX, let's return NULL
      goto err;
    }
  }

  // Finalizes the Encryption and handles the TAG
  if (1 != _encrypt_final_sym(ctx)) goto err;

  // Transfer Ownership to the output parameter
  ret->encryptionKey->data = ctx->k_enc.data;
  ctx->k_enc.data = NULL;

  ret->encryptionKey->length = ctx->k_enc.length;
  ctx->k_enc.length = 0;

  // Gets the Key Identifier for the recipient's key
  if (NULL == LIBEC_KEY_identifier(&ret->keyIdentifier, ctx->key, 0)) goto err;

  // Transfer Ownership of the encrypted data
  ret->value->data = ctx->enc_data;
  ret->value->length = ctx->enc_data_end;
  ctx->enc_data = NULL;

  // Sets the output parameter
  if (enc) *enc = ret;

  // Cleanup the Context
  LIBEC_CTX_cleanup(ctx);

  // Success
  return ret;

err:

  // Cleanup the Context
  LIBEC_CTX_cleanup(ctx);

  // Free Memory
  if (!(enc && *enc)) {
    // Free Memory
    if (ret) LIBEC_ENCRYPTED_free(ret);
  }

  // Fixe the output param
  if (enc) * enc = NULL;

  return NULL;
}

LIBEC_ENCRYPTED * LIBEC_encrypt(LIBEC_CTX       ** ctx,
                                            LIBEC_ENCRYPTED ** enc,
		                                        LIBEC_KEY        * key,
		                                        LIBEC_ENC_ALG      algor,
											                      LIBEC_ENC_MODE     mode,
											                      const unsigned char    * data,
											                      size_t                   data_size) {

  LIBEC_ENCRYPTED * ret = NULL;
    // Return Structure

  LIBEC_CTX * inner_ctx = NULL;
    // Local CTX

  // Checks the ctx parameter
  if (ctx && *ctx) {
    /// Gets the context from the parameter
    inner_ctx = *ctx;
    // Cleanup the context
    LIBEC_CTX_cleanup(inner_ctx);
  } else {
    // Let's make sure we have a good inner_ctx
    if ((inner_ctx = LIBEC_CTX_new()) == NULL) goto err;
  }

  // Input check
  if (!key || !data || !data_size) return NULL;

  // Initializes the Encryption Operation
  if (NULL == LIBEC_encrypt_init(&inner_ctx,
                                        key,
                                        algor,
                                        mode,
                                        data,
                                        data_size)) goto err;

  // Finalizes the Encryption
  if ((ret = LIBEC_encrypt_final(enc, inner_ctx)) == NULL) goto err;

  // Fix the output
  if (ctx) *ctx = inner_ctx;
  if (enc) *enc = ret;

  // All Done
  return ret;

err:

  // Fixes the Context
  if (!(ctx && *ctx)) {
    // Frees the Context Memory
    if (inner_ctx) LIBEC_CTX_free(inner_ctx);
    *ctx = NULL;
  }

  // Fixes the Encrypted
  if (!(enc && *enc)) {
    // Frees the Encrypted memory container
    if (ret) LIBEC_ENCRYPTED_free(ret);
    *enc = NULL;
  }

  // Reports the error
  return NULL;
}

LIBEC_CTX * LIBEC_encrypt_sym_direct(LIBEC_CTX       ** ctx,
                                                 unsigned char         ** enc_data,
                                                 size_t                 * enc_data_size,
                                                 LIBEC_KEY        * key,
                                                 LIBEC_ENC_ALG      algor,
                                                 LIBEC_ENC_MODE     mode,
                                                 const unsigned char    * data,
                                                 size_t                   data_size) {

  LIBEC_CTX * ret = NULL;
    // Return Structure

  int outl = 0;
    // Size of encrypted data

  // Input Check
  if (!enc_data || !enc_data_size || !key || !data || !data_size) return NULL;

  // Sets the defaults
  if (!algor) algor = LIBEC_ENC_ALG_DEFAULT;
  if (!mode) mode = LIBEC_ENC_MODE_DEFAULT;

  // Key Type Check
  if (LIBEC_KEY_TYPE_SYMMETRIC != key->type) return NULL;

  // Checks algorithm and Key Size
  switch (algor) {

    // AES 128 (any mode)
    case LIBEC_ENC_ALG_AES_128: {
      if (key->skey.data_size < 16) return NULL;
    } break;

    // AES 192 (any mode)
    case LIBEC_ENC_ALG_AES_192: {
      if (key->skey.data_size < 24) return NULL;
    } break;

    // AES 256 (any mode)
    case LIBEC_ENC_ALG_AES_256: {
      if (key->skey.data_size < 32) return NULL;
    } break;

    // Unsupported Algorithm
    default: {
      return NULL;
    } break;
  }

  // Checks the ctx parameter
  if (ctx && *ctx) {
    /// Gets the context from the parameter
    ret = *ctx;
    // Cleanup the context
    LIBEC_CTX_cleanup(ret);
  } else {
    // Let's make sure we have a good inner_ctx
    if ((ret = LIBEC_CTX_new()) == NULL) goto err;
  }

  // Initializes the data encryption
  if (NULL == _encrypt_init_sym(&ret, algor, mode, key->skey.data, key->skey.data_size))
    goto err;

  // If there is data to be encrypted, let's encrypt it
  if (data && data_size) {

    // Encrypts the Data to the output buffer
    if (1 != EVP_EncryptUpdate(ret->cipher_ctx,
                               ret->enc_data + ret->enc_data_next,
                               &outl,
                               data,
                               data_size)) goto err;

    // Updates the size of the written data
    ret->enc_data_next += outl;
  }

  // Finalizes the Encryption and handles the TAG
  if (1 != _encrypt_final_sym(ret)) goto err;

  // Transfers the Data
  *enc_data = ret->enc_data;
  *enc_data_size = ret->enc_data_end;

  // Remove reference from the context
  ret->enc_data = NULL;
  ret->enc_data_end = 0;

  // Returns the context
  return ret;

err:

  // Free Memory
  if (!(ctx && *ctx)) {
    if (ret) LIBEC_CTX_free(ret);
  }

  // Fixes outbound parameters
  if (enc_data) *enc_data = NULL;
  if (enc_data_size) *enc_data_size = 0;

  // Reports the error
  return NULL;

}

LIBEC_CTX * LIBEC_decrypt_init(LIBEC_CTX             ** ctx,
                                           unsigned char               ** buffer,
                                           size_t                       * buffer_size,
                                           const LIBEC_ENCRYPTED  * enc,
                                           const LIBEC_KEY        * key) {

  LIBEC_CTX * ret = NULL;
    // Return Structure

  LIBEC_DIGEST * dgst = NULL;
    // Key Identifier for the decryption key

  LIBEC_KEY * d_key = NULL;
    // Decryption Key

  int outl = 0;
  int proc = 0;
  unsigned char * dec_data = NULL;
  size_t dec_data_size = 0;
    // Decrypted Data Pointers

  // Input Check
  if (!enc || !enc->keyIdentifier || !enc->encryptionKey || !enc->value || !key) return NULL;

  // Checks the output buffer (we need a correct size)
  if (buffer && *buffer && (!buffer_size || !*buffer_size)) return NULL;

  // Checks the ctx parameter
  if (ctx && *ctx) {
    /// Gets the context from the parameter
    ret = *ctx;
    // Cleanup the context
    LIBEC_CTX_cleanup(ret);
  } else {
    // Let's make sure we have a good inner_ctx
    if ((ret = LIBEC_CTX_new()) == NULL) goto err;
  }

  // Checks we have the right key
  if (NULL == LIBEC_KEY_identifier(&dgst,
                                          key,
                                          LIBEC_DIGEST_algor(enc->keyIdentifier))) goto err;

  // Compares the key Identifier
  if (0 != LIBEC_DIGEST_cmp(dgst, enc->keyIdentifier)) goto err;

  // Gets the Decryption Key
  if (NULL == _decrypt_key(&ret, &d_key, enc->encryptionKey, key)) goto err;

  // Initializes Data Decryption
  if (NULL == _decrypt_init_sym(&ret,
                                enc->value->data,
                                enc->value->length,
                                d_key->skey.data,
                                d_key->skey.data_size)) goto err;

  // Decrypts the data if the buffer was provided
  if (buffer && buffer_size) {

    // Required Space
    proc = ret->dec_data_size - (ret->dec_data_next - ret->dec_data);

    // Allocates the required memory
    if ((*buffer = OPENSSL_malloc(proc
                                  + EVP_CIPHER_CTX_block_size(ret->cipher_ctx))) == NULL) goto err;
    // Decrypts the data
    if (1 != EVP_DecryptUpdate(ret->cipher_ctx,
                               *buffer,
                               &outl,
                               ret->dec_data_next,
                               proc)) goto err;

    // Adjust the output size parameter
    *buffer_size = outl;

    // Fixes the next pointer
    ret->dec_data_next += proc;
  }

  // Frees internal memory usage
  if (dgst) LIBEC_DIGEST_free(dgst);
  if (d_key) LIBEC_KEY_free(d_key);

  // Fixes the output parameter
  if (ctx) *ctx = ret;

  // Success
  return ret;

err:

  // Free internal memory usage
  if (dgst) LIBEC_DIGEST_free(dgst);
  if (d_key) LIBEC_KEY_free(d_key);

  // Free output variables
  if (!(ctx && *ctx)) {
    if (ret) LIBEC_CTX_free(ret);
    if (ctx) *ctx = NULL;
  }

  // Fixes output buffer (if not provided)
  if (buffer && *buffer) OPENSSL_free(*buffer);
  if (buffer_size) *buffer_size = 0;

  // Report the error
  return NULL;
}

int LIBEC_decrypt_update(unsigned char               ** data,      /* OUT    */
				                       size_t                       * data_size, /* IN/OUT */
				                       const LIBEC_ENCRYPTED  * enc,       /* Unused */
				                       LIBEC_CTX              * ctx) {

  unsigned char * buffer = NULL;
  int decrypted = 0;

  size_t proc = 0;
  size_t available = 0;

  // Input Check
  if (!data || !data_size || !ctx) return -1;

  // Checks we have data to decrypt, if none, we return 0
  if (ctx->dec_data_next >= ctx->dec_data + ctx->dec_data_size) return 0;

  // Available data for decryption
  available = ctx->dec_data_size - (ctx->dec_data_next - ctx->dec_data);

  // In case we have the output buffer already allocated, we tailor the
  // amount of data to be decrypted to the size of the provided buffer
  if (*data && *data_size) {
    proc = *data_size - EVP_CIPHER_CTX_block_size(ctx->cipher_ctx) >= available ?
        available : *data_size - EVP_CIPHER_CTX_block_size(ctx->cipher_ctx);
    buffer = *data;
  } else {
    // Required Space
    proc = ctx->dec_data_size - (ctx->dec_data_next - ctx->dec_data);
    if ((buffer = OPENSSL_malloc(proc + EVP_CIPHER_CTX_block_size(ctx->cipher_ctx))) == NULL)
      goto err;
  }

  // Decrypts the data
  if (1 != EVP_DecryptUpdate(ctx->cipher_ctx,
                             buffer,
                             &decrypted,
                             ctx->dec_data_next,
                             proc)) goto err;

  // Fixes the next pointer
  ctx->dec_data_next += proc;

  // Adjust the output size parameter
  if (!(*data)) {
    *data = buffer;
    *data_size = decrypted;
  }

  // Success
  return decrypted;

err:

  // Free allocated memory
  if (!(*data)) {
    if (buffer) OPENSSL_free(buffer);
  }

  // Reports the error
  return -1;
}

int LIBEC_decrypt_final(unsigned char    ** data,
							                size_t 	          * size,
							                LIBEC_CTX 	* ctx) {

  // Input Check
  if (!ctx || !ctx->dec_data || !ctx->dec_data_size || !data || !*data || !size)
    goto err;

  // Finalize Decryption (assumes one block of data is available)
  if (1 != _decrypt_final_sym(*data, size, ctx)) goto err;

  // Remove the link for encrypted data
  ctx->dec_data = NULL;
  ctx->dec_data_size = 0;
  ctx->dec_data_next = 0;

  // Cleanup the context
  LIBEC_CTX_cleanup(ctx);

  // Success
  return 1;

err:

  // Cleanup the context
  LIBEC_CTX_cleanup(ctx);
  return 0;
}

LIBEC_CTX * LIBEC_decrypt(LIBEC_CTX             ** ctx,
                                      unsigned char               ** data,
                                      size_t                       * size,
                                      const LIBEC_ENCRYPTED  * enc,
                                      const LIBEC_KEY        * key) {

  LIBEC_CTX * ret = NULL;
    // Return Structure

  // Initializes the decryption and decrypts the data
  if ((ret = LIBEC_decrypt_init(ctx, data, size, enc, key)) == NULL) goto err;

  // Finalizes the Decryption
  if (1 != LIBEC_decrypt_final(data, size, ret)) goto err;

  // Returns the success
  return ret;

err:

  // Free Memory
  if (!(ctx && *ctx)) {
    if (ret) LIBEC_CTX_free(ret);
    if (ctx) *ctx = NULL;
  }

  // Reports the error
  return 0;
}

LIBEC_CTX * LIBEC_decrypt_sym_direct(LIBEC_CTX       ** ctx,
                                                 unsigned char         ** data,
                                                 size_t                 * data_size,
                                                 const unsigned char    * enc,
                                                 size_t                   enc_size,
                                                 const LIBEC_KEY  * key) {

  LIBEC_CTX * ret = NULL;
    // Return Structure

  int outl = 0;
  int proc = 0;
  unsigned char * dec_data = NULL;
  size_t dec_data_size = 0;
    // Decrypted Data Pointers

  // Input Check
  if (!enc || !enc_size || !data || !data_size || !key) return NULL;

  // Checks the ctx parameter
  if (ctx && *ctx) {
    /// Gets the context from the parameter
    ret = *ctx;
    // Cleanup the context
    LIBEC_CTX_cleanup(ret);
  } else {
    // Let's make sure we have a good inner_ctx
    if ((ret = LIBEC_CTX_new()) == NULL) goto err;
  }

  // Initializes Data Decryption
  if (NULL == _decrypt_init_sym(&ret,
                                enc,
                                enc_size,
                                key->skey.data,
                                key->skey.data_size)) goto err;

  // Decrypts the data if the buffer was provided
  if (data && data_size) {

    // Required Space
    proc = ret->dec_data_size - (ret->dec_data_next - ret->dec_data);

    // Allocates the required memory
    if ((*data = OPENSSL_malloc(proc
                                  + EVP_CIPHER_CTX_block_size(ret->cipher_ctx))) == NULL) goto err;
    // Decrypts the data
    if (1 != EVP_DecryptUpdate(ret->cipher_ctx,
                               *data,
                               &outl,
                               ret->dec_data_next,
                               proc)) goto err;

    // Adjust the output size parameter
    *data_size = outl;

    // Fixes the next pointer
    ret->dec_data_next += proc;
  }

  // Finalize Decryption (assumes one block of data is available)
  if (1 != _decrypt_final_sym(*data, data_size, ret)) goto err;

  // Remove the link for encrypted data
  ret->dec_data = NULL;
  ret->dec_data_size = 0;
  ret->dec_data_next = 0;

  // Cleanup the context
  LIBEC_CTX_cleanup(ret);

  // Fixes the output parameter
  if (ctx) *ctx = ret;

  // Success
  return ret;

err:

  // Free output variables
  if (!(ctx && *ctx)) {
    if (ret) LIBEC_CTX_free(ret);
    if (ctx) *ctx = NULL;
  }

  // Report the error
  return NULL;

}

#ifdef  __cplusplus
}
#endif
