/**
 * DPAPI CREDHIST entry (AES-256/SHA-512)
 *
 * Key derivation (GPU):
 *   sha1_pass  = SHA1( password.UTF16LE )
 *   enc_key    = HMAC-SHA1( sha1_pass, SID.UTF16LE+NUL )
 *   PBKDF2-HMAC-SHA512( enc_key, iv, rounds, dklen=48 )   → out64[0..5]
 *
 * Verification (GPU-side, last AES block only):
 *   aes_key = out64[0..3]  (first 32 bytes of PBKDF2 output)
 *   ct2     = enc[8..11]   (last 16-byte AES block = bytes 32-47 of ciphertext)
 *   ct1     = enc[4..7]    (previous AES block, used as CBC IV for ct2)
 *   pt2     = AES256_decrypt(ct2) XOR ct1
 *   pt2[1..3] == 0         (bytes 36-47 must be zero)
 *
 * Bytes 36-39 = Win10+ embedded NT null pad OR AES padding (both cases zero).
 * Bytes 40-47 = AES block padding (always zero).
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct dpapimk_tmp_v2
{
  u64 ipad64[8];
  u64 opad64[8];
  u64 dgst64[8];  /* dklen=48 needs only 1 SHA-512 PBKDF2 block */
  u64 out64[8];

} dpapimk_tmp_v2_t;

typedef struct dpapi_credhist_aes
{
  u32 revision;
  u32 SID[32];
  u32 SID_len;
  u32 iv[4];
  u32 enc[12];
  u32 sha_len;
  u32 nt_len;
} dpapi_credhist_aes_t;

/* ------------------------------------------------------------------ */

DECLSPEC void hmac_sha512_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, PRIVATE_AS u64x *ipad, PRIVATE_AS u64x *opad, PRIVATE_AS u64x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);

  w0[0] = h32_from_64 (digest[0]);
  w0[1] = l32_from_64 (digest[0]);
  w0[2] = h32_from_64 (digest[1]);
  w0[3] = l32_from_64 (digest[1]);
  w1[0] = h32_from_64 (digest[2]);
  w1[1] = l32_from_64 (digest[2]);
  w1[2] = h32_from_64 (digest[3]);
  w1[3] = l32_from_64 (digest[3]);
  w2[0] = h32_from_64 (digest[4]);
  w2[1] = l32_from_64 (digest[4]);
  w2[2] = h32_from_64 (digest[5]);
  w2[3] = l32_from_64 (digest[5]);
  w3[0] = h32_from_64 (digest[6]);
  w3[1] = l32_from_64 (digest[6]);
  w3[2] = h32_from_64 (digest[7]);
  w3[3] = l32_from_64 (digest[7]);
  w4[0] = 0x80000000;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = (128 + 64) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);
}

/* ------------------------------------------------------------------ */

KERNEL_FQ KERNEL_FA void m15930_init (KERN_ATTR_TMPS_ESALT (dpapimk_tmp_v2_t, dpapi_credhist_aes_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /* Step 1: sha1_pass = SHA1(password.UTF16LE) */

  sha1_ctx_t sha1_ctx;

  sha1_init (&sha1_ctx);

  sha1_update_global_utf16le_swap (&sha1_ctx, pws[gid].i, pws[gid].pw_len);

  sha1_final (&sha1_ctx);

  u32 digest_context[5];

  digest_context[0] = sha1_ctx.h[0];
  digest_context[1] = sha1_ctx.h[1];
  digest_context[2] = sha1_ctx.h[2];
  digest_context[3] = sha1_ctx.h[3];
  digest_context[4] = sha1_ctx.h[4];

  /* Step 2: enc_key = HMAC-SHA1(sha1_pass, SID.UTF16LE+NUL) */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = digest_context[0];
  w0[1] = digest_context[1];
  w0[2] = digest_context[2];
  w0[3] = digest_context[3];
  w1[0] = digest_context[4];
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_hmac_ctx_t hmac1_ctx;

  sha1_hmac_init_64 (&hmac1_ctx, w0, w1, w2, w3);

  sha1_hmac_update_global (&hmac1_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].SID, esalt_bufs[DIGESTS_OFFSET_HOST].SID_len);

  sha1_hmac_final (&hmac1_ctx);

  u32 key[5];

  key[0] = hmac1_ctx.opad.h[0];
  key[1] = hmac1_ctx.opad.h[1];
  key[2] = hmac1_ctx.opad.h[2];
  key[3] = hmac1_ctx.opad.h[3];
  key[4] = hmac1_ctx.opad.h[4];

  /* Step 3: init PBKDF2-HMAC-SHA512 with enc_key as password */

  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  w0[0] = key[0];
  w0[1] = key[1];
  w0[2] = key[2];
  w0[3] = key[3];
  w1[0] = key[4];
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = 0;

  sha512_hmac_ctx_t sha512_hmac_ctx;

  sha512_hmac_init_128 (&sha512_hmac_ctx, w0, w1, w2, w3, w4, w5, w6, w7);

  tmps[gid].ipad64[0] = sha512_hmac_ctx.ipad.h[0];
  tmps[gid].ipad64[1] = sha512_hmac_ctx.ipad.h[1];
  tmps[gid].ipad64[2] = sha512_hmac_ctx.ipad.h[2];
  tmps[gid].ipad64[3] = sha512_hmac_ctx.ipad.h[3];
  tmps[gid].ipad64[4] = sha512_hmac_ctx.ipad.h[4];
  tmps[gid].ipad64[5] = sha512_hmac_ctx.ipad.h[5];
  tmps[gid].ipad64[6] = sha512_hmac_ctx.ipad.h[6];
  tmps[gid].ipad64[7] = sha512_hmac_ctx.ipad.h[7];

  tmps[gid].opad64[0] = sha512_hmac_ctx.opad.h[0];
  tmps[gid].opad64[1] = sha512_hmac_ctx.opad.h[1];
  tmps[gid].opad64[2] = sha512_hmac_ctx.opad.h[2];
  tmps[gid].opad64[3] = sha512_hmac_ctx.opad.h[3];
  tmps[gid].opad64[4] = sha512_hmac_ctx.opad.h[4];
  tmps[gid].opad64[5] = sha512_hmac_ctx.opad.h[5];
  tmps[gid].opad64[6] = sha512_hmac_ctx.opad.h[6];
  tmps[gid].opad64[7] = sha512_hmac_ctx.opad.h[7];

  /* Seed PBKDF2 block 1: HMAC(enc_key, iv || 0x00000001).
   *same two-step approach as m15900 */

  w0[0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[0];
  w0[1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[1];
  w0[2] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[2];
  w0[3] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[3];
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = 0;

  sha512_hmac_update_128 (&sha512_hmac_ctx, w0, w1, w2, w3, w4, w5, w6, w7, 16);

  for (u32 i = 0, j = 1; i < 8; i += 8, j += 1)
  {
    sha512_hmac_ctx_t sha512_hmac_ctx2 = sha512_hmac_ctx;

    w0[0] = j;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
    w4[0] = 0;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = 0;

    sha512_hmac_update_128 (&sha512_hmac_ctx2, w0, w1, w2, w3, w4, w5, w6, w7, 4);

    sha512_hmac_final (&sha512_hmac_ctx2);

    tmps[gid].dgst64[i + 0] = sha512_hmac_ctx2.opad.h[0];
    tmps[gid].dgst64[i + 1] = sha512_hmac_ctx2.opad.h[1];
    tmps[gid].dgst64[i + 2] = sha512_hmac_ctx2.opad.h[2];
    tmps[gid].dgst64[i + 3] = sha512_hmac_ctx2.opad.h[3];
    tmps[gid].dgst64[i + 4] = sha512_hmac_ctx2.opad.h[4];
    tmps[gid].dgst64[i + 5] = sha512_hmac_ctx2.opad.h[5];
    tmps[gid].dgst64[i + 6] = sha512_hmac_ctx2.opad.h[6];
    tmps[gid].dgst64[i + 7] = sha512_hmac_ctx2.opad.h[7];

    tmps[gid].out64[i + 0] = tmps[gid].dgst64[i + 0];
    tmps[gid].out64[i + 1] = tmps[gid].dgst64[i + 1];
    tmps[gid].out64[i + 2] = tmps[gid].dgst64[i + 2];
    tmps[gid].out64[i + 3] = tmps[gid].dgst64[i + 3];
    tmps[gid].out64[i + 4] = tmps[gid].dgst64[i + 4];
    tmps[gid].out64[i + 5] = tmps[gid].dgst64[i + 5];
    tmps[gid].out64[i + 6] = tmps[gid].dgst64[i + 6];
    tmps[gid].out64[i + 7] = tmps[gid].dgst64[i + 7];
  }
}

/* ------------------------------------------------------------------ */

KERNEL_FQ KERNEL_FA void m15930_loop (KERN_ATTR_TMPS_ESALT (dpapimk_tmp_v2_t, dpapi_credhist_aes_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u64x ipad[8];
  u64x opad[8];

  ipad[0] = pack64v (tmps, ipad64, gid, 0);
  ipad[1] = pack64v (tmps, ipad64, gid, 1);
  ipad[2] = pack64v (tmps, ipad64, gid, 2);
  ipad[3] = pack64v (tmps, ipad64, gid, 3);
  ipad[4] = pack64v (tmps, ipad64, gid, 4);
  ipad[5] = pack64v (tmps, ipad64, gid, 5);
  ipad[6] = pack64v (tmps, ipad64, gid, 6);
  ipad[7] = pack64v (tmps, ipad64, gid, 7);

  opad[0] = pack64v (tmps, opad64, gid, 0);
  opad[1] = pack64v (tmps, opad64, gid, 1);
  opad[2] = pack64v (tmps, opad64, gid, 2);
  opad[3] = pack64v (tmps, opad64, gid, 3);
  opad[4] = pack64v (tmps, opad64, gid, 4);
  opad[5] = pack64v (tmps, opad64, gid, 5);
  opad[6] = pack64v (tmps, opad64, gid, 6);
  opad[7] = pack64v (tmps, opad64, gid, 7);

  u64x dgst[8];
  u64x out[8];

  dgst[0] = pack64v (tmps, dgst64, gid, 0);
  dgst[1] = pack64v (tmps, dgst64, gid, 1);
  dgst[2] = pack64v (tmps, dgst64, gid, 2);
  dgst[3] = pack64v (tmps, dgst64, gid, 3);
  dgst[4] = pack64v (tmps, dgst64, gid, 4);
  dgst[5] = pack64v (tmps, dgst64, gid, 5);
  dgst[6] = pack64v (tmps, dgst64, gid, 6);
  dgst[7] = pack64v (tmps, dgst64, gid, 7);

  out[0] = pack64v (tmps, out64, gid, 0);
  out[1] = pack64v (tmps, out64, gid, 1);
  out[2] = pack64v (tmps, out64, gid, 2);
  out[3] = pack64v (tmps, out64, gid, 3);
  out[4] = pack64v (tmps, out64, gid, 4);
  out[5] = pack64v (tmps, out64, gid, 5);
  out[6] = pack64v (tmps, out64, gid, 6);
  out[7] = pack64v (tmps, out64, gid, 7);

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];
    u32x w4[4];
    u32x w5[4];
    u32x w6[4];
    u32x w7[4];

    w0[0] = h32_from_64 (out[0]);
    w0[1] = l32_from_64 (out[0]);
    w0[2] = h32_from_64 (out[1]);
    w0[3] = l32_from_64 (out[1]);
    w1[0] = h32_from_64 (out[2]);
    w1[1] = l32_from_64 (out[2]);
    w1[2] = h32_from_64 (out[3]);
    w1[3] = l32_from_64 (out[3]);
    w2[0] = h32_from_64 (out[4]);
    w2[1] = l32_from_64 (out[4]);
    w2[2] = h32_from_64 (out[5]);
    w2[3] = l32_from_64 (out[5]);
    w3[0] = h32_from_64 (out[6]);
    w3[1] = l32_from_64 (out[6]);
    w3[2] = h32_from_64 (out[7]);
    w3[3] = l32_from_64 (out[7]);
    w4[0] = 0x80000000;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = (128 + 64) * 8;

    hmac_sha512_run_V (w0, w1, w2, w3, w4, w5, w6, w7, ipad, opad, dgst);

    out[0] ^= dgst[0];
    out[1] ^= dgst[1];
    out[2] ^= dgst[2];
    out[3] ^= dgst[3];
    out[4] ^= dgst[4];
    out[5] ^= dgst[5];
    out[6] ^= dgst[6];
    out[7] ^= dgst[7];
  }

  unpack64v (tmps, dgst64, gid, 0, dgst[0]);
  unpack64v (tmps, dgst64, gid, 1, dgst[1]);
  unpack64v (tmps, dgst64, gid, 2, dgst[2]);
  unpack64v (tmps, dgst64, gid, 3, dgst[3]);
  unpack64v (tmps, dgst64, gid, 4, dgst[4]);
  unpack64v (tmps, dgst64, gid, 5, dgst[5]);
  unpack64v (tmps, dgst64, gid, 6, dgst[6]);
  unpack64v (tmps, dgst64, gid, 7, dgst[7]);

  unpack64v (tmps, out64, gid, 0, out[0]);
  unpack64v (tmps, out64, gid, 1, out[1]);
  unpack64v (tmps, out64, gid, 2, out[2]);
  unpack64v (tmps, out64, gid, 3, out[3]);
  unpack64v (tmps, out64, gid, 4, out[4]);
  unpack64v (tmps, out64, gid, 5, out[5]);
  unpack64v (tmps, out64, gid, 6, out[6]);
  unpack64v (tmps, out64, gid, 7, out[7]);
}

/* ------------------------------------------------------------------ */

/*
 * m15930_comp — GPU-side AES-256-CBC verification (last block only).
 *
 * AES-256 key = PBKDF2 output bytes 0-31 = out64[0..3] (big-endian u64).
 * Extract as 8 × u32 via h32_from_64_S / l32_from_64_S.
 *
 * Only the last AES block (ct2 = enc[8..11]) is decrypted.
 * CBC XOR uses the previous ciphertext block (ct1 = enc[4..7]).
 *
 * esalt enc[] is stored as BE u32 (hex_to_u32 + byte_swap_32 in parser).
 * AES256_decrypt expects BE u32 — pass enc[] directly without extra swap.
 *
 * Plaintext bytes 36-47 of pt2 (pt2[1..3]) must be zero:
 *   pt2[0] = bytes 32-35 (NTLM[12-15], not zero)
 *   pt2[1] = bytes 36-39 (Win10+ null pad or AES padding — zero)
 *   pt2[2] = bytes 40-43 (AES padding — zero)
 *   pt2[3] = bytes 44-47 (AES padding — zero)
 */
KERNEL_FQ KERNEL_FA void m15930_comp (KERN_ATTR_TMPS_ESALT (dpapimk_tmp_v2_t, dpapi_credhist_aes_t))
{
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
  }

  SYNC_THREADS ();

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /* AES-256 key = first 32 bytes of PBKDF2 output = out64[0..3] */

  u32 ukey[8];

  ukey[0] = h32_from_64_S (tmps[gid].out64[0]);
  ukey[1] = l32_from_64_S (tmps[gid].out64[0]);
  ukey[2] = h32_from_64_S (tmps[gid].out64[1]);
  ukey[3] = l32_from_64_S (tmps[gid].out64[1]);
  ukey[4] = h32_from_64_S (tmps[gid].out64[2]);
  ukey[5] = l32_from_64_S (tmps[gid].out64[2]);
  ukey[6] = h32_from_64_S (tmps[gid].out64[3]);
  ukey[7] = l32_from_64_S (tmps[gid].out64[3]);

  u32 ks[60];

  AES256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  /* Load ct2 = enc[8..11] (last AES block = ciphertext bytes 32-47).
   * esalt enc[] is stored as BE u32 (parser applies byte_swap_32 after
   * hex_to_u32).  AES256_decrypt expects BE u32 — pass directly. */

  u32 ct2[4];

  ct2[0] = esalt_bufs[DIGESTS_OFFSET_HOST].enc[ 8];
  ct2[1] = esalt_bufs[DIGESTS_OFFSET_HOST].enc[ 9];
  ct2[2] = esalt_bufs[DIGESTS_OFFSET_HOST].enc[10];
  ct2[3] = esalt_bufs[DIGESTS_OFFSET_HOST].enc[11];

  u32 pt2[4];

  AES256_decrypt (ks, ct2, pt2, s_td0, s_td1, s_td2, s_td3, s_td4);

  /* CBC XOR with ct1 = enc[4..7] (previous ciphertext block) */

  pt2[0] ^= esalt_bufs[DIGESTS_OFFSET_HOST].enc[4];
  pt2[1] ^= esalt_bufs[DIGESTS_OFFSET_HOST].enc[5];
  pt2[2] ^= esalt_bufs[DIGESTS_OFFSET_HOST].enc[6];
  pt2[3] ^= esalt_bufs[DIGESTS_OFFSET_HOST].enc[7];

  if (pt2[1] != 0) return;
  if (pt2[2] != 0) return;
  if (pt2[3] != 0) return;

  #define il_pos 0

  if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
  {
    mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
  }
}
