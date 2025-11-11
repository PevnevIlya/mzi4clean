package com.example.mzi.crypto;

import java.nio.charset.StandardCharsets;

public final class GOST3411_2012 {

    private static final byte[] S = {
            0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1,
            0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF,
            0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0,
            0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0xB,0xA,0x5,0xE,0x3,0x9,0x0,
            0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC,
            0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0xE,0x3,0x0,
            0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7,
            0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2
    };

    private static final long[] TAU = {
            0,8,16,24,32,40,48,56,1,9,17,25,33,41,49,57,2,10,18,26,34,42,50,58,
            3,11,19,27,35,43,51,59,4,12,20,28,36,44,52,60,5,13,21,29,37,45,53,61,
            6,14,22,30,38,46,54,62,7,15,23,31,39,47,55,63
    };

    private static final long[][] C = {
            {0x00L,0x00L,0x00L,0x00L,0x00L,0x00L,0x00L,0x00L},
            {0xb1L,0x08L,0x5bL,0xdaL,0x1eL,0xcaL,0xdaL,0xe9L},
            {0xebL,0xcbL,0x2fL,0x81L,0xc0L,0x65L,0x7cL,0x1fL},
            {0x2fL,0x6eL,0x14L,0x6cL,0x73L,0x17L,0x62L,0x3aL},
            {0x4bL,0x91L,0x81L,0xffL,0x36L,0x77L,0x9fL,0x96L},
            {0x5bL,0xa4L,0x20L,0x25L,0x3dL,0xbcL,0x2aL,0x2cL},
            {0xb9L,0x0bL,0x60L,0x8dL,0x6bL,0x45L,0x9aL,0x8dL},
            {0x8fL,0xe3L,0x6aL,0x53L,0x7dL,0x9cL,0x4cL,0x01L},
            {0x6dL,0x37L,0xa6L,0x34L,0x73L,0x75L,0x81L,0x0eL},
            {0x9cL,0x7fL,0x5cL,0x4eL,0x49L,0x4bL,0x7bL,0x9dL},
            {0x7dL,0x1aL,0x2fL,0x8cL,0x58L,0x3fL,0x73L,0x2eL},
            {0x2fL,0x8cL,0x58L,0x3fL,0x73L,0x2eL,0x7dL,0x1aL}
    };

    private static long[] xor(long[] a, long[] b) {
        long[] c = new long[8];
        for (int i = 0; i < 8; i++) c[i] = a[i] ^ b[i];
        return c;
    }

    private static long[] add512(long[] a, long[] b) {
        long carry = 0;
        long[] c = new long[8];
        for (int i = 7; i >= 0; i--) {
            long t = a[i] + b[i] + carry;
            c[i] = t & 0xFFFFFFFFFFFFFFFFL;
            carry = t >>> 64;
        }
        return c;
    }

    private static long[] S(long[] x) {
        long[] r = new long[8];
        for (int i = 0; i < 64; i++) {
            int idx = (int)((x[i>>3] >>> ((7-(i&7))<<3)) & 0xFF);
            long v = S[idx];
            r[i>>3] |= v << ((7-(i&7))<<3);
        }
        return r;
    }

    private static long[] P(long[] x) {
        long[] r = new long[8];
        for (int i = 0; i < 64; i++) {
            long b = (x[i>>3] >>> ((7-(i&7))<<3)) & 1;
            r[TAU[i]>>3] |= b << ((7-(TAU[i]&7))<<3);
        }
        return r;
    }

    private static long[] L(long[] x) {
        long[] r = new long[8];
        for (int i = 0; i < 64; i++) {
            long t = 0;
            for (int j = 0; j < 64; j++) {
                if (((x[j>>3] >>> ((7-(j&7))<<3)) & 1) == 1) {
                    t ^= (0x8e2010b8L >>> (j&7)) & 1L;
                }
            }
            if (t == 1) r[i>>3] ^= 1L << ((7-(i&7))<<3);
        }
        return r;
    }

    private static long[] E(long[] k, long[] m) {
        long[] state = xor(k, m);
        long[] key = k.clone();
        for (int i = 0; i < 12; i++) {
            state = S(state);
            state = P(state);
            state = L(state);
            key = xor(key, C[i]);
            key = S(key);
            key = P(key);
            key = L(key);
            state = xor(state, key);
        }
        return state;
    }

    private static long[] g(long[] n, long[] m, long[] h) {
        long[] k = S(P(L(xor(h, n))));
        long[] t = E(k, m);
        return xor(xor(t, h), m);
    }

    private static long[] bytesToBlock(byte[] b, int off) {
        long[] r = new long[8];
        for (int i = 0; i < 64; i++) {
            int pos = off + (i^7);
            r[i>>3] = (r[i>>3] << 8) | (b[pos] & 0xFF);
        }
        return r;
    }

    public static String hash512(byte[] data) {
        return bytesToHex(compute(data, 64));
    }

    public static String hash256(byte[] data) {
        return bytesToHex(compute(data, 32));
    }

    private static byte[] compute(byte[] msg, int outLen) {
        long[] h = new long[8];
        long[] n = new long[8];
        long[] sigma = new long[8];

        int pos = 0;
        while (pos + 64 <= msg.length) {
            long[] m = bytesToBlock(msg, pos);
            h = g(n, m, h);
            n = add512(n, new long[]{0,0,0,0,0,0,0,512});
            sigma = add512(sigma, m);
            pos += 64;
        }

        byte[] last = new byte[64];
        int rem = msg.length - pos;
        System.arraycopy(msg, pos, last, 0, rem);
        last[rem] = 0x01;

        long[] m = bytesToBlock(last, 0);
        h = g(n, m, h);
        long lenBits = (long)msg.length * 8;
        n = add512(n, new long[]{0,0,0,0,0,0,0,lenBits});
        sigma = add512(sigma, m);

        h = g(new long[8], new long[8], h);
        h = g(new long[8], sigma, h);

        byte[] result = new byte[outLen];
        for (int i = 0; i < outLen; i++) {
            result[i] = (byte)(h[i>>>3] >>> ((7-(i&7))<<3));
        }
        return result;
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte v : b) sb.append(String.format("%02x", v));
        return sb.toString();
    }
}