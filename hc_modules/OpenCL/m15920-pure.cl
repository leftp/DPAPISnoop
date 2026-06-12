/**
 * DPAPI CREDHIST entry (3DES + HMAC-SHA1)
 *
 * Key derivation:
 *   sha1_pass = SHA1(password.UTF16LE)
 *   enc_key   = HMAC-SHA1(sha1_pass, (SID + NUL).UTF16LE)
 *   derived   = PBKDF2-HMAC-SHA1(enc_key, iv, rounds, dklen=32)
 *   3DES key  = derived[ 0..23]
 *   3DES IV   = derived[24..31]
 *
 * Verification (GPU-side, last DES block only):
 *   pt4 = 3DES-EDE-decrypt(ct[4]) XOR ct[3]
 *   pt4[1] == 0x00000000  (bytes 36-39, zero-padding)
 *
 * Plaintext layout: sha1_prev(20) | ntlm_prev(16) | zero_pad(4)
 *
 * FALSE-POSITIVE NOTE: only 4 zero bytes are checked — 1/2^32 rate.
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct dpapi_credhist_tmp
{
  u32 ipad[5];
  u32 opad[5];
  u32 dgst[10];
  u32 out[10];

} dpapi_credhist_tmp_t;

typedef struct dpapi_credhist
{
  u32 SID[32];
  u32 SID_len;

  u32 iv[4];

  u32 enc[16];
  u32 enc_len;

  u32 sha_len;
  u32 nt_len;

  u32 revision;

} dpapi_credhist_t;

DECLSPEC void hmac_sha1_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ KERNEL_FA void m15920_init (KERN_ATTR_TMPS_ESALT (dpapi_credhist_tmp_t, dpapi_credhist_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * Stage 1: sha1_pass = SHA1(password.UTF16LE)
   */

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_global_utf16le_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha1_final (&ctx);

  u32 digest_context[5];

  digest_context[0] = ctx.h[0];
  digest_context[1] = ctx.h[1];
  digest_context[2] = ctx.h[2];
  digest_context[3] = ctx.h[3];
  digest_context[4] = ctx.h[4];

  /**
   * Stage 2: enc_key = HMAC-SHA1(sha1_pass, SID_utf16le_with_nul)
   */

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

  sha1_hmac_ctx_t ctx2;

  sha1_hmac_init_64 (&ctx2, w0, w1, w2, w3);

  sha1_hmac_update_global (&ctx2, esalt_bufs[DIGESTS_OFFSET_HOST].SID, esalt_bufs[DIGESTS_OFFSET_HOST].SID_len);

  sha1_hmac_final (&ctx2);

  u32 key[5];

  key[0] = ctx2.opad.h[0];
  key[1] = ctx2.opad.h[1];
  key[2] = ctx2.opad.h[2];
  key[3] = ctx2.opad.h[3];
  key[4] = ctx2.opad.h[4];

  /**
   * Stage 3: PBKDF2-HMAC-SHA1(enc_key, iv, rounds, dklen=32)
   *
   * Two PBKDF2 blocks (i=0,5) produce 40 bytes; we use only the first 32.
   */

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

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init_64 (&sha1_hmac_ctx, w0, w1, w2, w3);

  tmps[gid].ipad[0] = sha1_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha1_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha1_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha1_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha1_hmac_ctx.ipad.h[4];

  tmps[gid].opad[0] = sha1_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha1_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha1_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha1_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha1_hmac_ctx.opad.h[4];

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

  sha1_hmac_update_64 (&sha1_hmac_ctx, w0, w1, w2, w3, 16);

  for (u32 i = 0, j = 1; i < 8; i += 5, j += 1)
  {
    sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx;

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

    sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);

    sha1_hmac_final (&sha1_hmac_ctx2);

    tmps[gid].dgst[i + 0] = sha1_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = sha1_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = sha1_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = sha1_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = sha1_hmac_ctx2.opad.h[4];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 4] = tmps[gid].dgst[i + 4];
  }
}

KERNEL_FQ KERNEL_FA void m15920_loop (KERN_ATTR_TMPS_ESALT (dpapi_credhist_tmp_t, dpapi_credhist_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[5];
  u32x opad[5];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);

  for (u32 i = 0; i < 8; i += 5)
  {
    u32x dgst[5];
    u32x out[5];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);

    out[0] = packv (tmps, out, gid, i + 0);
    out[1] = packv (tmps, out, gid, i + 1);
    out[2] = packv (tmps, out, gid, i + 2);
    out[3] = packv (tmps, out, gid, i + 3);
    out[4] = packv (tmps, out, gid, i + 4);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = out[0];
      w0[1] = out[1];
      w0[2] = out[2];
      w0[3] = out[3];
      w1[0] = out[4];
      w1[1] = 0x80000000;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 20) * 8;

      hmac_sha1_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);

    unpackv (tmps, out, gid, i + 0, out[0]);
    unpackv (tmps, out, gid, i + 1, out[1]);
    unpackv (tmps, out, gid, i + 2, out[2]);
    unpackv (tmps, out, gid, i + 3, out[3]);
    unpackv (tmps, out, gid, i + 4, out[4]);
  }
}

/*
 * m15920_comp — GPU-side 3DES-CBC verification (last block only).
 *
 * PBKDF2 output layout (out[0..7], big-endian u32):
 *   K1 = out[0..1]  (8 bytes, DES key 1)
 *   K2 = out[2..3]  (8 bytes, DES key 2)
 *   K3 = out[4..5]  (8 bytes, DES key 3)
 *   IV = out[6..7]  (8 bytes, CBC IV for block 0 — not needed for last-block-only check)
 *
 * Ciphertext layout (esalt enc[], stored LE after byte_swap_32 in parser):
 *   ct[3] = enc[6..7]   (the CBC chaining value for the last block)
 *   ct[4] = enc[8..9]   (the last ciphertext block, bytes 32-39 of enc)
 *
 */
KERNEL_FQ KERNEL_FA void m15920_comp (KERN_ATTR_TMPS_ESALT (dpapi_credhist_tmp_t, dpapi_credhist_t))
{
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /* Key schedule: hc_swap32_S converts PBKDF2 out[] to the byte order
   * same pattern as m15300-pure.cl */

  u32 K1c[16], K1d[16];
  u32 K2c[16], K2d[16];
  u32 K3c[16], K3d[16];

  _des_crypt_keysetup (hc_swap32_S (tmps[gid].out[0]), hc_swap32_S (tmps[gid].out[1]), K1c, K1d, s_skb);
  _des_crypt_keysetup (hc_swap32_S (tmps[gid].out[2]), hc_swap32_S (tmps[gid].out[3]), K2c, K2d, s_skb);
  _des_crypt_keysetup (hc_swap32_S (tmps[gid].out[4]), hc_swap32_S (tmps[gid].out[5]), K3c, K3d, s_skb);

  u32 ct4[2];

  ct4[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].enc[8]);
  ct4[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].enc[9]);

  /* 3DES-EDE decrypt */

  u32 tmp[2];

  _des_crypt_decrypt (tmp, ct4, K3c, K3d, s_SPtrans);
  _des_crypt_encrypt (ct4, tmp, K2c, K2d, s_SPtrans);
  _des_crypt_decrypt (tmp, ct4, K1c, K1d, s_SPtrans);

  /* CBC XOR with ct[3] = enc[6..7] */

  tmp[0] ^= hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].enc[6]);
  tmp[1] ^= hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].enc[7]);

  if (tmp[1] != 0) return;

  #define il_pos 0

  if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
  {
    mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
  }
}
