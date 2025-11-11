package com.example.AuthenticationService.util;

public final class GOST3411_2012 {

    private static final byte[][] S_BOX = {
            {0x0C, 0x04, 0x06, 0x02, 0x0A, 0x05, 0x0B, 0x09, 0x0E, 0x08, 0x0D, 0x07, 0x00, 0x03, 0x0F, 0x01},
            {0x06, 0x08, 0x02, 0x03, 0x09, 0x0A, 0x05, 0x0C, 0x01, 0x0E, 0x04, 0x07, 0x0B, 0x0D, 0x00, 0x0F},
            {0x0B, 0x03, 0x05, 0x08, 0x02, 0x0F, 0x0A, 0x0D, 0x0E, 0x01, 0x07, 0x04, 0x0C, 0x09, 0x06, 0x00},
            {0x0C, 0x08, 0x02, 0x01, 0x0D, 0x04, 0x0F, 0x06, 0x07, 0x0B, 0x0A, 0x05, 0x0E, 0x03, 0x09, 0x00},
            {0x07, 0x0F, 0x05, 0x0A, 0x08, 0x01, 0x06, 0x0D, 0x00, 0x09, 0x03, 0x0E, 0x0B, 0x04, 0x02, 0x0C},
            {0x05, 0x0D, 0x0F, 0x06, 0x09, 0x02, 0x0C, 0x0A, 0x0B, 0x07, 0x08, 0x01, 0x04, 0x0E, 0x03, 0x00},
            {0x08, 0x0E, 0x02, 0x05, 0x06, 0x09, 0x01, 0x0C, 0x0F, 0x04, 0x0B, 0x00, 0x0D, 0x0A, 0x03, 0x07},
            {0x01, 0x07, 0x0E, 0x0D, 0x00, 0x05, 0x08, 0x03, 0x04, 0x0F, 0x0A, 0x06, 0x09, 0x0C, 0x0B, 0x02}
    };

    private static final long[][] A = new long[64][8];
    static {
        long[] vec = {0x8e,0x11,0x98,0xa2,0x3f,0x1c,0xc4,0xf5};
        for (int i = 0; i < 64; i++) {
            for (int j = 0; j < 8; j++) {
                A[i][j] = vec[j];
            }
            vec = lps(vec);
        }
    }

    private static final long[][] C = {
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01},
            {0xdd,0x80,0x64,0x6b,0xa2,0x52,0x80,0x3f},
            {0x4e,0x6c,0x74,0x8c,0x2b,0x8e,0x8a,0x2f},
            {0x6c,0x2b,0x8e,0x8a,0x2f,0x4e,0x6c,0x74},
            {0x8c,0x2b,0x8e,0x8a,0x2f,0x6c,0x2b,0x8e},
            {0x2f,0x6c,0x2b,0x8e,0x8a,0x2f,0x6c,0x2b},
            {0x8a,0x2f,0x6c,0x2b,0x8e,0x8a,0x2f,0x6c},
            {0x2b,0x8e,0x8a,0x2f,0x6c,0x2b,0x8e,0x8a},
            {0x8e,0x8a,0x2f,0x6c,0x2b,0x8e,0x8a,0x2f},
            {0x6c,0x2b,0x8e,0x8a,0x2f,0x6c,0x2b,0x8e},
            {0x8a,0x2f,0x6c,0x2b,0x8e,0x8a,0x2f,0x6c},
            {0x2f,0x6c,0x2b,0x8e,0x8a,0x2f,0x6c,0x2b}
    };

    private static long[] lps(long[] x) {
        long[] res = new long[8];
        for (int i = 0; i < 64; i++) {
            long bit = 0;
            for (int j = 0; j < 8; j++) {
                if ((x[j] & (1L << (63 - i))) != 0) bit ^= 1L;
            }
            for (int j = 0; j < 8; j++) {
                if ((i % 8) == j) res[j] ^= bit << (63 - i % 64);
            }
        }
        return res;
    }

    private static long[] xor(long[] a, long[] b) {
        long[] c = new long[8];
        for (int i = 0; i < 8; i++) c[i] = a[i] ^ b[i];
        return c;
    }

    private static long[] addMod512(long[] a, long[] b) {
        long carry = 0;
        long[] c = new long[8];
        for (int i = 7; i >= 0; i--) {
            long sum = a[i] + b[i] + carry;
            c[i] = sum & 0xFFFFFFFFFFFFFFFFL;
            carry = sum >>> 64;
        }
        return c;
    }

    private static long[] s(long[] x) {
        long[] res = new long[8];
        for (int i = 0; i < 8; i++) {
            long word = x[i];
            for (int j = 0; j < 8; j++) {
                int nibble = (int) ((word >>> (56 - j*8)) & 0xFF);
                int row = nibble >>> 4;
                int col = nibble & 0x0F;
                int substituted = S_BOX[j][col] << 4 | S_BOX[j][row];
                res[i] = (res[i] << 8) | substituted;
            }
        }
        return res;
    }

    private static long[] p(long[] x) {
        long[] res = new long[8];
        for (int i = 0; i < 64; i++) {
            int src = i % 8;
            int dst = (i * 8) % 64;
            long bit = (x[src] >>> (63 - (i % 8) * 8)) & 1;
            res[dst / 8] |= bit << (63 - (dst % 8) * 8);
        }
        return res;
    }

    private static long[] l(long[] x) {
        long[] res = new long[8];
        for (int i = 0; i < 64; i++) {
            long bit = 0;
            for (int j = 0; j < 8; j++) {
                if ((x[j] & (1L << (63 - i))) != 0) bit ^= A[i][j];
            }
            int wordIdx = i / 8;
            int bitInWord = 56 - (i % 8) * 8;
            res[wordIdx] |= bit << bitInWord;
        }
        return res;
    }

    private static long[] E(long[] K, long[] m) {
        long[] state = xor(K, m);
        for (int i = 0; i < 12; i++) {
            state = s(state);
            state = p(state);
            state = l(state);
            K = xor(K, C[i]);
            K = s(K);
            K = p(K);
            K = l(K);
            state = xor(state, K);
        }
        return state;
    }

    private static long[] g(long[] N, long[] m, long[] h) {
        long[] K = xor(h, N);
        K = s(K); K = p(K); K = l(K);
        long[] t = E(K, m);
        t = xor(t, h);
        return xor(t, m);
    }

    public static String hash512(byte[] data) {
        return bytesToHex(compute(data, 512));
    }

    public static String hash256(byte[] data) {
        byte[] full = compute(data, 512);
        byte[] truncated = new byte[32];
        System.arraycopy(full, 0, truncated, 0, 32);
        return bytesToHex(truncated);
    }

    private static byte[] compute(byte[] msg, int hashSize) {
        long[] h = new long[8];
        long[] N = new long[8];
        long[] Sigma = new long[8];

        int len = msg.length * 8;
        int pos = 0;

        while (pos + 64 <= msg.length) {
            byte[] block = new byte[64];
            System.arraycopy(msg, pos, block, 0, 64);
            long[] m = bytesToLongsBE(reverse(block));
            h = g(N, m, h);
            N = addMod512(N, new long[]{0,0,0,0,0,0,0,512});
            Sigma = addMod512(Sigma, m);
            pos += 64;
        }

        // padding
        int remaining = msg.length - pos;
        byte[] last = new byte[64];
        System.arraycopy(msg, pos, last, 0, remaining);
        last[remaining] = 0x01;

        long[] m = bytesToLongsBE(reverse(last));
        h = g(N, m, h);
        N = addMod512(N, new long[]{0,0,0,0,0,0,0,len});
        Sigma = addMod512(Sigma, m);

        h = g(new long[8], new long[8], h);
        h = g(new long[8], Sigma, h);

        byte[] result = new byte[64];
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                result[i*8 + j] = (byte) (h[i] >>> (56 - j*8));
            }
        }
        return result;
    }

    private static long[] bytesToLongsBE(byte[] b) {
        long[] res = new long[8];
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                res[i] = (res[i] << 8) | (b[i*8 + j] & 0xFF);
            }
        }
        return res;
    }

    private static byte[] reverse(byte[] b) {
        byte[] r = new byte[b.length];
        for (int i = 0; i < b.length; i++) r[i] = b[b.length - 1 - i];
        return r;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
