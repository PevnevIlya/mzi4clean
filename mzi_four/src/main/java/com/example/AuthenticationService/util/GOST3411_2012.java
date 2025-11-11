package com.example.AuthenticationService.util;

public final class GOST3411_2012 {

    private static final byte[][] sbox = {
            {12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1},
            {6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15},
            {11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0},
            {12,8,2,1,13,4,15,6,7,11,10,5,14,3,9,0},
            {7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12},
            {5,13,15,6,9,2,12,10,11,7,8,1,4,14,3,0},
            {8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7},
            {1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2}
    };

    private static final byte[] tau = {
            0,8,16,24,32,40,48,56,
            1,9,17,25,33,41,49,57,
            2,10,18,26,34,42,50,58,
            3,11,19,27,35,43,51,59,
            4,12,20,28,36,44,52,60,
            5,13,21,29,37,45,53,61,
            6,14,22,30,38,46,54,62,
            7,15,23,31,39,47,55,63
    };

    private static final long[][] consts = {
            {},
            {0x00L,0x00L,0x00L,0x00L,0x00L,0x00L,0x00L,0x01L},
            {0xb1L,0x08L,0x5bL,0xdaL,0x1eL,0xcaL,0xdaL,0xe9L},
            {0xabL,0x1eL,0x5bL,0xdaL,0x1eL,0xcaL,0xdaL,0xe9L},
            {0x6bL,0x1eL,0x5bL,0xdaL,0x1eL,0xcaL,0xdaL,0xe9L},
            {0x2bL,0x1eL,0x5bL,0xdaL,0x1eL,0xcaL,0xdaL,0xe9L},
            {0x0bL,0x1eL,0x5bL,0xdaL,0x1eL,0xcaL,0xdaL,0xe9L},
            {0x8bL,0x1eL,0x5bL,0xdaL,0x1eL,0xcaL,0xdaL,0xe9L},
            {0x4bL,0x1eL,0x5bL,0xdaL,0x1eL,0xcaL,0xdaL,0xe9L},
            {0x2bL,0x1eL,0x5bL,0xdaL,0x1eL,0xcaL,0xdaL,0xe9L},
            {0x0bL,0x1eL,0x5bL,0xdaL,0x1eL,0xcaL,0xdaL,0xe9L},
            {0x8bL,0x1eL,0x5bL,0xdaL,0x1eL,0xcaL,0xdaL,0xe9L}
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
            c[i] = t;
            carry = t >>> 64;
        }
        return c;
    }

    private static long[] S(long[] x) {
        long[] r = new long[8];
        for (int i = 0; i < 64; i++) {
            int v = (int)(x[i/8] >>> ((7-(i%8))*8)) & 0xFF;
            int s = sbox[i/8][v];
            r[i/8] |= (long)s << ((7-(i%8))*8);
        }
        return r;
    }

    private static long[] P(long[] x) {
        long[] r = new long[8];
        for (int i = 0; i < 64; i++) {
            long bit = (x[i/8] >>> ((7-(i%8))*8)) & 1;
            int pos = tau[i];
            r[pos/8] |= bit << ((7-(pos%8))*8);
        }
        return r;
    }

    private static long[] L(long[] x) {
        long[] r = new long[8];
        for (int i = 0; i < 64; i++) {
            long acc = 0;
            for (int j = 0; j < 64; j++) {
                if (((x[j/8] >>> ((7-(j%8))*8)) & 1) == 1) {
                    acc ^= 0x8e20baa7628f3d8fL >>> (j%64);
                }
            }
            if ((acc & 1) == 1) r[i/8] |= 1L << ((7-(i%8))*8);
        }
        return r;
    }

    private static long[] E(long[] k, long[] a) {
        long[] state = xor(a, k);
        for (int i = 1; i <= 12; i++) {
            state = S(state);
            state = P(state);
            state = L(state);
            long[] ki = xor(k, consts[i]);
            ki = S(ki); ki = P(ki); ki = L(ki);
            state = xor(state, ki);
        }
        return state;
    }

    private static long[] compress(long[] h, long[] n, long[] m) {
        long[] k = xor(h, n);
        k = S(k); k = P(k); k = L(k);
        long[] t = E(k, m);
        return xor(xor(t, h), m);
    }

    public static String hash512(byte[] data) {
        return bytesToHex(compute(data, 64));
    }

    public static String hash256(byte[] data) {
        return bytesToHex(compute(data, 32));
    }

    private static byte[] compute(byte[] msg, int len) {
        long[] h = new long[8];
        long[] n = new long[8];
        long[] sum = new long[8];

        int pos = 0;
        while (pos + 64 <= msg.length) {
            long[] block = new long[8];
            for (int i = 0; i < 64; i++) {
                block[7-(i/8)] |= (long)(msg[pos+i] & 0xFF) << ((i%8)*8);
            }
            h = compress(h, n, block);
            n = add512(n, new long[]{0,0,0,0,0,0,0,512});
            sum = add512(sum, block);
            pos += 64;
        }

        byte[] pad = new byte[64];
        int rest = msg.length - pos;
        System.arraycopy(msg, pos, pad, 0, rest);
        pad[rest] = 0x01;

        long[] block = new long[8];
        for (int i = 0; i < 64; i++) {
            block[7-(i/8)] |= (long)(pad[i] & 0xFF) << ((i%8)*8);
        }
        h = compress(h, n, block);
        long bitlen = (long)msg.length * 8;
        n = add512(n, new long[]{0,0,0,0,0,0,0,bitlen});
        sum = add512(sum, block);

        h = compress(h, new long[8], h);
        h = compress(h, new long[8], sum);

        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte)(h[7-(i/8)] >>> ((i%8)*8));
        }
        return out;
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte v : b) sb.append(String.format("%02x", v));
        return sb.toString();
    }
}