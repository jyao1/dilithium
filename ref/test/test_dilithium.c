#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "../randombytes.h"
#include "../sign.h"
#include "../poly.h"
#include "../polyvec.h"

#define MLEN 59
#define NTESTS 10000

int main1(void)
{
  size_t i, j;
  int ret;
  size_t mlen, smlen;
  uint8_t b;
  uint8_t m[MLEN + CRYPTO_BYTES];
  uint8_t m2[MLEN + CRYPTO_BYTES];
  uint8_t sm[MLEN + CRYPTO_BYTES];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  for(i = 0; i < NTESTS; ++i) {
    randombytes(m, MLEN);

    crypto_sign_keypair(pk, sk);
    crypto_sign(sm, &smlen, m, MLEN, sk);
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);

    if(ret) {
      fprintf(stderr, "Verification failed\n");
      return -1;
    }
    if(smlen != MLEN + CRYPTO_BYTES) {
      fprintf(stderr, "Signed message lengths wrong\n");
      return -1;
    }
    if(mlen != MLEN) {
      fprintf(stderr, "Message lengths wrong\n");
      return -1;
    }
    for(j = 0; j < MLEN; ++j) {
      if(m2[j] != m[j]) {
        fprintf(stderr, "Messages don't match\n");
        return -1;
      }
    }

    randombytes((uint8_t *)&j, sizeof(j));
    do {
      randombytes(&b, 1);
    } while(!b);
    sm[j % (MLEN + CRYPTO_BYTES)] += b;
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);
    if(!ret) {
      fprintf(stderr, "Trivial forgeries possible\n");
      return -1;
    }
  }

  printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_BYTES = %d\n", CRYPTO_BYTES);

  return 0;
}

void print_hex16(char *name, uint8_t *buffer, size_t len)
{
  size_t i;
  if (name != NULL) {
    printf ("%s: ", name);
  }
  for (i = 0; i < len; i++) {
    printf ("%02x, ", buffer[i]);
  }
  printf ("\n");
}

void print_hex(char *name, uint8_t *buffer, size_t len)
{
  size_t i;
  if (name != NULL) {
    printf ("%s: ", name);
  }
  for (i = 0; i < len; i++) {
    printf ("%d, ", buffer[i]);
  }
  printf ("\n");
}

void print_poly(char *name, poly *p)
{
  size_t i;
  if (name != NULL) {
    printf ("%s: ", name);
  } else {
    printf ("<p>: ");
  }
  for (i = 0; i < N; i++) {
    printf ("%d, ", p->coeffs[i]);
  }
  printf ("\n");
}

void print_polyvecl(char *name, polyvecl *pv)
{
  size_t i;
  if (name != NULL) {
    printf ("%s: ", name);
  } else {
    printf ("<pv>: ");
  }
  for (i = 0; i < L; i++) {
    print_poly (NULL, &pv->vec[i]);
  }
  printf ("\n");
}

void print_polyveck(char *name, polyveck *pv)
{
  size_t i;
  if (name != NULL) {
    printf ("%s: ", name);
  } else {
    printf ("<pv>: ");
  }
  for (i = 0; i < K; i++) {
    print_poly (NULL, &pv->vec[i]);
  }
  printf ("\n");
}

void print_matrix(char *name, polyvecl pv[K])
{
  size_t i;
  if (name != NULL) {
    printf ("%s: ", name);
  }
  for (i = 0; i < K; i++) {
    print_polyvecl (NULL, &pv[i]);
  }
  printf ("\n");
}

void test_kyber_key_api ()
{
    int ret;
    size_t siglen;
    uint8_t m[MLEN] = {0};
    uint8_t sig[CRYPTO_BYTES] = {0};
    uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {0};
    uint8_t sk[CRYPTO_SECRETKEYBYTES] = {0};

    crypto_sign_keypair(pk, sk);
    print_hex ("-- pk", pk, sizeof(pk));
    print_hex ("-- sk", sk, sizeof(sk));

    crypto_sign_signature(sig, &siglen, m, MLEN, sk);
    print_hex ("-- sig", sig, siglen);

    ret = crypto_sign_verify(sig, siglen, m, MLEN, pk);
    if(ret) {
      fprintf(stderr, "Verification failed2\n");
    } else {
      fprintf(stderr, "Verification passed2\n");
    }
}

void test_sample_in_ball ()
{
  poly c = {0};
  uint8_t seed[SEEDBYTES] = {0};

  poly_challenge (&c, seed);
  print_poly ("-- sample in ball - ", &c);
}

int main(void)
{
  {volatile int ___i=1;while(___i);}
  //test_kyber_key_api();

  test_sample_in_ball();
  return 0;
}