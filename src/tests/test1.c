#include "test1.h"

// ------------------------------------------------------------------------- //
//                             PROTOTYPES                                    //
// ------------------------------------------------------------------------- //

// Info Print Function
void banner();

// Saves Output Data
int save_data(const char * name, unsigned char * data, size_t size);
 
// Generic Tests for Library functions
int crypto_tests();

// ------------------------------------------------------------------------- //
//                              FUNCTIONS                                    //
// ------------------------------------------------------------------------- //

int save_data(const char * name, unsigned char * data, size_t size) {

  FILE * f = NULL;

  if ((f = fopen(name, "w")) == NULL) return 0;
  fwrite(data, size, 1, f);
  fclose(f);

  return 1;
}

int crypto_tests() {

  // Time Information
  struct timeval  time[2], avg[2];
  struct timezone tz;

  // Keys Containers
  LIBEC_KEY * k_ec = NULL;
  LIBEC_KEY * k_rsa = NULL;
  LIBEC_KEY * k_tmp = NULL;
  LIBEC_KEY * k_aes = NULL;

  // Signature CTX
  LIBEC_CTX * ctx = NULL;

  // Digest Container
  LIBEC_DIGEST * dgst = NULL;

  // Signature Container
  LIBEC_SIGNATURE * sig = NULL;

  // Encrypted Data Container
  LIBEC_ENCRYPTED * enc = NULL;

  // Buffer
  unsigned char * buf = NULL;
  size_t buf_size = 0;

  // Temporary buffer
  unsigned char * buf_other = NULL;
  size_t buf_other_size = 0;

  // Temporary buffer
  const unsigned char * tmp_buf = NULL;
  size_t tmp_buf_size = 0;

  // Random data to be signed
  unsigned char rand_data[40];

  // Index
  int idx = 0;


  //
  // RSA Crypto
  // 

  printf("* RSA Crypto Tests:\n");

  printf("  - Generating RSA Key ...");
  gettimeofday(&time[0], &tz);
  if ((k_rsa = LIBEC_KEY_gen_rsa(NULL, 0)) == NULL) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (time = %llu)\n", timeval_diff(&time[0], &time[1]));

  printf("  - Saving RSA key (Private) ... ");
  if (1 != LIBEC_KEY_encode_private(&buf, &buf_size, k_rsa)) goto err;
  printf("Ok (size = %lu)\n", buf_size);

  save_data("output/rsa_priv.der", buf, buf_size);

  printf("  - Parsing RSA key (Private) ... ");
  if (NULL == LIBEC_KEY_decode_private(&k_tmp,
                                        LIBEC_KEY_TYPE_ASYMMETRIC,
                                        buf,
                                        buf_size)) goto err;
  printf("Ok\n");

  // Memory Cleanup
  OPENSSL_free(buf);
  buf = NULL;

  printf("  - Saving RSA key (Public) ... ");
  if (1 != LIBEC_KEY_encode_public(&buf, &buf_size, k_rsa)) goto err;
  printf("Ok (size = %lu)\n", buf_size);

  save_data("output/rsa_pub.der", buf, buf_size);

  printf("  - Parsing RSA key (Public) ... ");
  if (NULL == LIBEC_KEY_decode_public(&k_tmp, buf, buf_size)) goto err;
  printf("Ok\n");

  // Memory Cleanup
  OPENSSL_free(buf);
  buf = NULL;


  //
  // Elliptic Curve
  //

  printf("\n* ECDSA Crypto Tests:\n");

  printf("  - Generating EC key ... ");
  gettimeofday(&time[0], &tz);
  if ((k_ec = LIBEC_KEY_gen_ec(NULL, 0)) == NULL) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (time = %llu)\n", timeval_diff(&time[0], &time[1]));

  printf("  - Saving EC key (Private) ... ");
  if (1 != LIBEC_KEY_encode_private(&buf, &buf_size, k_ec)) goto err;
  printf("Ok\n");

  save_data("output/ec_priv.der", buf, buf_size);

  printf("  - Parsing EC key (Private) ... ");
  if (NULL == LIBEC_KEY_decode_private(&k_tmp,
                                          LIBEC_KEY_TYPE_ASYMMETRIC,
                                          buf,
                        buf_size)) goto err;
  printf("Ok\n");

  // Memory Cleanup
  OPENSSL_free(buf);
  buf = NULL;

  printf("  - Saving EC key (Public) ... ");
  if (1 != LIBEC_KEY_encode_public(&buf, &buf_size, k_ec)) goto err;
  printf("Ok\n");

  save_data("output/ec_pub.der", buf, buf_size);

  printf("  - Parsing EC key (Public) ... ");
  if (NULL == LIBEC_KEY_decode_public(&k_tmp, buf, buf_size)) goto err;
  printf("Ok\n");

  // Memory Cleanup
  OPENSSL_free(buf);
  buf = NULL;


  //
  // Key Derivation (DH vs. ECDH)
  //

  printf("\n* DH vs ECDH Tests:\n");

  printf("  - Generating Peer Key (EC) ... ");
  if (NULL == LIBEC_KEY_gen_ec(&k_tmp, 0)) goto err;
  printf("Ok\n");

  printf("  - Deriving Symmetric Key (ECDH) ... ");
  gettimeofday(&time[0], &tz);
  if (NULL == LIBEC_ecdh_derive(&k_aes, k_ec, k_tmp)) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (size = %lu, time = %llu)\n", k_aes->skey.data_size,
      timeval_diff(&time[0], &time[1]));

  printf("  - Saving Symmetric AES key (Private) ... ");
  if (1 != LIBEC_KEY_encode_private(&buf, &buf_size, k_aes)) goto err;
  printf("Ok\n");

  save_data("output/aes_priv.der", buf, buf_size);

  // Memory Cleanup
  OPENSSL_free(buf);
  buf = NULL;

  //
  // Signing and Verifying
  //

  printf("\n* Sign and Verify Tests:\n");

  printf("  - Generating Random Data (%lu) ... ", sizeof(rand_data));
  if (!RAND_bytes(rand_data, sizeof(rand_data))) goto err;
  printf("Ok\n");

  printf("  - Signing %lu data (EC) ... ", sizeof(rand_data));
  gettimeofday(&time[0], &tz);
  if (NULL == LIBEC_sign(&ctx, &sig, k_ec, 0, rand_data, sizeof(rand_data))) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (time = %llu)\n", timeval_diff(&time[0], &time[1]));

  printf("  - Encoding EC signature ... ");
  gettimeofday(&time[0], &tz);
  if (1 != LIBEC_SIGNATURE_encode(&buf, &buf_size, sig)) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (size = %lu, time = %llu)\n", buf_size, timeval_diff(&time[0], &time[1]));

  save_data("output/ec_signature.der", buf, buf_size);

  printf("  - Verifying %lu data (EC) ... ", sizeof(rand_data));
  gettimeofday(&time[0], &tz);
  if (1 != LIBEC_verify(&ctx, sig, k_ec, rand_data, sizeof(rand_data))) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (time = %llu)\n", timeval_diff(&time[0], &time[1]));

  // Memory Cleanup
  OPENSSL_free(buf);
  buf = NULL;

  printf("  - Signing %lu data (RSA) ... ", sizeof(rand_data));
  gettimeofday(&time[0], &tz);
  if (NULL == LIBEC_sign_init(&ctx, k_rsa, 0, rand_data, sizeof(rand_data))) goto err;
  if (NULL == LIBEC_sign_final(&sig, ctx)) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (time = %llu)\n", timeval_diff(&time[0], &time[1]));

  printf("  - Encoding RSA signature ... ");
  gettimeofday(&time[0], &tz);
  if (1 != LIBEC_SIGNATURE_encode(&buf, &buf_size, sig)) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (size = %lu, time = %llu)\n", buf_size, timeval_diff(&time[0], &time[1]));

  save_data("output/rsa_signature.der", buf, buf_size);

  printf("  - Verifying %lu data (RSA) ... ", sizeof(rand_data));
  gettimeofday(&time[0], &tz);
  if (NULL == LIBEC_verify_init(&ctx, sig, k_rsa, rand_data, sizeof(rand_data))) goto err;
  if (1 != LIBEC_verify_final(ctx)) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (size = %zu, time = %llu)\n", buf_size, timeval_diff(&time[0], &time[1]));

  // Memory Cleanup
  OPENSSL_free(buf);
  buf = NULL;

  printf("  - Signing %lu data (HMAC) ... ", sizeof(rand_data));
  gettimeofday(&time[0], &tz);
  if (NULL == LIBEC_sign_init(&ctx, k_aes, LIBEC_DIGEST_ALG_UNKNOWN, NULL, 0)) goto err;
  if (1 != LIBEC_sign_update(ctx, rand_data, sizeof(rand_data))) goto err;
  if (NULL == LIBEC_sign_final(&sig, ctx)) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (time = %llu)\n", timeval_diff(&time[0], &time[1]));

  printf("  - Encoding HMAC signature ... ");
  gettimeofday(&time[0], &tz);
  if (1 != LIBEC_SIGNATURE_encode(&buf, &buf_size, sig)) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (size = %lu, time = %llu)\n", buf_size, timeval_diff(&time[0], &time[1]));

  save_data("output/aes_signature.der", buf, buf_size);

  printf("  - Verifying %lu data (HMAC) ... ", sizeof(rand_data));
  gettimeofday(&time[0], &tz);
  if (NULL == LIBEC_verify_init(&ctx, sig, k_aes, rand_data, sizeof(rand_data))) goto err;
  if (1 != LIBEC_verify_final(ctx)) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (time = %llu)\n", timeval_diff(&time[0], &time[1]));

  // Memory Cleanup
  OPENSSL_free(buf);
  buf = NULL;


  //
  // Digest
  //

  printf("\n* Digest Tests:\n");

  printf("  - Generating new digest (%lu) ... ", sizeof(rand_data));
  gettimeofday(&time[0], &tz);
  if ((dgst = LIBEC_DIGEST_new(NULL, 0, rand_data, sizeof(rand_data))) == NULL) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (time = %llu)\n", timeval_diff(&time[0], &time[1]));

  printf("  - Encoding Digest ... ");
  if (1 != LIBEC_DIGEST_encode(&buf, &buf_size, dgst)) goto err;
  printf("Ok (size = %zu)\n", buf_size);

  save_data("output/digest.der", buf, buf_size);

  printf("  - Decoding Digest ... ");
  if (NULL == LIBEC_DIGEST_decode(&dgst, &tmp_buf, buf, buf_size)) goto err;
  printf("Ok (read = %zu)\n", (tmp_buf ? (tmp_buf - buf) : 0));

  printf("  - Retrieving Digest Algorithm ... %d\n",
      LIBEC_DIGEST_algor(dgst));

  printf("  - Retrieving Digest Size ... Ok (size = %zu)\n",
      LIBEC_DIGEST_value(NULL, dgst));

  printf("  - Retrieving Digest Value ... ");
  if (0 == LIBEC_DIGEST_value(&tmp_buf, dgst)) goto err;
  printf("Ok (buf = %p)\n", tmp_buf);

  // Memory Cleanup
  OPENSSL_free(buf);
  buf = NULL;

  //
  // Key Identifiers
  //

  printf("\n* Key Identifiers Tests:\n");

  printf("  - Retrieving Key Identifier (EC Key) ... ");
  gettimeofday(&time[0], &tz);
  if (NULL == LIBEC_KEY_identifier(&dgst, k_ec, 0)) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (time = %llu)\n", timeval_diff(&time[0], &time[1]));

  printf("  - Retrieving Key Identifier (RSA Key) ... ");
  gettimeofday(&time[0], &tz);
  if (NULL == LIBEC_KEY_identifier(&dgst, k_rsa, 0)) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (time = %llu)\n", timeval_diff(&time[0], &time[1]));

  printf("  - Retrieving Key Identifier (AES Key) ... ");
  gettimeofday(&time[0], &tz);
  if (NULL == LIBEC_KEY_identifier(&dgst, k_aes, 0)) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (time = %llu)\n", timeval_diff(&time[0], &time[1]));


  //
  // Encryption and Decryption
  //

  printf("\n* Encryption and Decryption Tests:\n");

  printf("  - Encrypting Random Data (RSA Key) ... ");
  gettimeofday(&time[0], &tz);
  if (NULL == LIBEC_encrypt_init(&ctx, k_rsa, 0, LIBEC_ENC_MODE_CBC, rand_data, sizeof(rand_data))) goto err;
  if (NULL == LIBEC_encrypt_final(&enc, ctx)) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (time = %llu)\n", timeval_diff(&time[0], &time[1]));

  printf("  - Encoding Encrypted Data ... ");
  if (1 != LIBEC_ENCRYPTED_encode(&buf, &buf_size, enc)) goto err;
  printf("Ok\n");

  save_data("output/encrypted_data_rsa.der", buf, buf_size);

  printf("  - Decoding Encrypted Data ... ");
  if (NULL == LIBEC_ENCRYPTED_decode(&enc, NULL, buf, buf_size)) goto err;
  printf("Ok\n");

  // Cleanup Memory
  OPENSSL_free(buf);
  buf = NULL;

  printf("  - Decrypting Encrypted Data (RSA Key) ... ");
  if (NULL == LIBEC_decrypt_init(&ctx, &buf, &buf_size, enc, k_rsa)) goto err;
  if (1 != LIBEC_decrypt_final(&buf, &buf_size, ctx)) goto err;
  printf("Ok\n");

  // Cleanup Memory
  OPENSSL_free(buf);
  buf = NULL;

  printf("  - Encrypting Random Data (AES Key) ... ");
  gettimeofday(&time[0], &tz);
  if (NULL == LIBEC_encrypt(&ctx, &enc, k_aes, 0, 0, rand_data, sizeof(rand_data))) goto err;
  gettimeofday(&time[1], &tz);
  printf("Ok (time = %llu)\n", timeval_diff(&time[0], &time[1]));

  printf("  - Encoding Encrypted Data ... ");
  if (1 != LIBEC_ENCRYPTED_encode(&buf, &buf_size, enc)) goto err;
  printf("Ok\n");

  save_data("output/encrypted_data_aes.der", buf, buf_size);

  printf("  - Decoding Encrypted Data ... ");
  if (NULL == LIBEC_ENCRYPTED_decode(&enc, NULL, buf, buf_size)) goto err;
  printf("Ok\n");

  // Cleanup Memory
  OPENSSL_free(buf);
  buf = NULL;

  printf("  - Decrypting Encrypted Data (AES Key) ... ");
  if (NULL == LIBEC_decrypt(&ctx, &buf, &buf_size, enc, k_aes)) goto err;
  printf("Ok\n");

  // Cleanup Memory
  OPENSSL_free(buf);
  buf = NULL;

  printf("  - Encrypt Direct (Sym) ... ");
  if (NULL == LIBEC_encrypt_sym_direct(&ctx,
                                             &buf,
                                             &buf_size,
                                             k_aes,
                                             0,
                                             0,
                                             rand_data,
                                             sizeof(rand_data))) goto err;
  printf("Ok\n");


  printf("  - Decrypting Direct (Sym) ... ");
  if (NULL == LIBEC_decrypt_sym_direct(&ctx,
                                             &buf_other,
                                             &buf_other_size,
                                             buf,
                                             buf_size,
                                             k_aes)) goto err;
  printf("Ok\n");

  // Cleanup Memory
  OPENSSL_free(buf_other);
  buf_other = NULL;
  OPENSSL_free(buf);
  buf = NULL;

  // Memory Cleanup
  if (buf) {
    OPENSSL_free(buf);
    buf = NULL;
  }

end:

  // All Done
  printf("\n");

  // Free Memory
  if (dgst) LIBEC_DIGEST_free(dgst);

  if (k_ec ) LIBEC_KEY_free(k_ec);
  if (k_rsa) LIBEC_KEY_free(k_rsa);
  if (k_aes) LIBEC_KEY_free(k_aes);
  if (k_tmp) LIBEC_KEY_free(k_tmp);

  if (sig) LIBEC_SIGNATURE_free(sig);
  if (ctx) LIBEC_CTX_free(ctx);

  if (enc) LIBEC_ENCRYPTED_free(enc);

  if (buf) OPENSSL_free(buf);

  return 1;

err:

  fflush(NULL);

  fprintf(stderr, "[ERROR] ");
  ERR_print_errors_fp(stderr);
  fprintf(stderr, "\n");

  if (k_ec) LIBEC_KEY_free(k_ec);
  if (k_rsa) LIBEC_KEY_free(k_rsa);
  if (k_aes) LIBEC_KEY_free(k_aes);
  if (k_tmp) LIBEC_KEY_free(k_tmp);

  if (dgst) LIBEC_DIGEST_free(dgst);
  if (sig) LIBEC_SIGNATURE_free(sig);
  if (ctx) LIBEC_CTX_free(ctx);

  return 0;
}

int memory_tests() {

  struct timeval  time[2], avg[2];
  struct timezone tz;
    // Time Information

  unsigned char rand_data[16] = { 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };

  unsigned char * message = (unsigned char *)"Hello from Max";
  size_t message_size = strlen((char *)message);

  LIBEC_CTX       * ctx = NULL;
  LIBEC_SIGNATURE * sig = NULL;
  LIBEC_KEY       * key = NULL;
  LIBEC_DIGEST    * dgst = NULL;
  LIBEC_ENCRYPTED * enc = NULL;

  unsigned char * buf = 0;
  size_t buf_size = 0;

  printf("* Memory Tests:\n");

  printf("  - Generating New Key ... ");
  if (NULL == LIBEC_KEY_gen_aes(&key, 0)) goto err;
  printf("Ok\n");

  printf("  - Encrypting Data ... ");
  if (NULL == LIBEC_encrypt_init(&ctx,
                                        key,
                                        LIBEC_ENC_ALG_AES_256,
                                        LIBEC_ENC_MODE_GCM,
                                        rand_data,
                                        sizeof(rand_data))) goto err;
  printf(" ... ");
  if (NULL == LIBEC_encrypt_final(&enc, ctx)) goto err;
  printf("Ok\n");

  printf("  - Encoding Encrypted Data ... ");
  if (1 != LIBEC_ENCRYPTED_encode(&buf, &buf_size, enc)) goto err;
  printf("Ok\n");

  save_data("output/encrypted_data.der", buf, buf_size);

  OPENSSL_free(buf);
  buf = NULL;

  printf("  - Decrypting Data ...");
  if (NULL == LIBEC_decrypt_init(&ctx, &buf, &buf_size, enc, key)) goto err;
  if (1 != LIBEC_decrypt_final(&buf, &buf_size, ctx)) goto err;
  printf("Ok\n");

  OPENSSL_free(buf);
  buf = NULL;

end:

  // All Done
  printf("\n");

  if (dgst) LIBEC_DIGEST_free(dgst);

  if (enc) LIBEC_ENCRYPTED_free(enc);
  if (ctx) LIBEC_CTX_free(ctx);
  if (sig) LIBEC_SIGNATURE_free(sig);
  if (key) LIBEC_KEY_free(key);

  return 1;

err:

  if (dgst) LIBEC_DIGEST_free(dgst);

  if (enc) LIBEC_ENCRYPTED_free(enc);
  if (ctx) LIBEC_CTX_free(ctx);
  if (sig) LIBEC_SIGNATURE_free(sig);
  if (key) LIBEC_KEY_free(key);

  return 0;

}

// ------------------------------------------------------------------------- //
//                                    MAIN                                   //
// ------------------------------------------------------------------------- //

int main() {

  // Pretty Output
  banner();

  // Initialization
  LIBEC_init();

  // Memory Tests
  // if (1 != memory_tests()) goto err;

  // Crypto Tests
  if (1 != crypto_tests()) goto err;

  // All Done
  printf("* All Done\n\n");

  LIBEC_cleanup();

  return 0;

err:

  printf("ERROR: ");
  ERR_print_errors_fp(stderr);

  LIBEC_cleanup();

  printf("\n\n* Aborted\n\n");
  return 1;
}

// ------------------------------------------------------------------------- //
//                           AUXILLARY FUNCTIONS                             //
// ------------------------------------------------------------------------- //

void banner() {
  fprintf(stdout, "\n");
  fprintf(stdout, "OpenCA's Easy Crypto Library - v %s\n", _APP_VERSION_);
  fprintf(stdout, "[Original Author: Massimiliano Pala <madwolf@openca.org>]\n");
  fprintf(stdout, "Copyright (C) Massimiliano Pala and OpenCA Labs, 2011\n");
  fprintf(stdout, "All Rights Reserved\n\n");
}

