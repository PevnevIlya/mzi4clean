package com.example.AuthenticationService.util;

public final class SHA1 {

    public static String hash(byte[] input) {
        int[] H = {
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0
        };

        byte[] padded = padMessage(input);
        int n = padded.length / 64;

        for (int i = 0; i < n; i++) {
            int[] W = new int[80];
            byte[] block = new byte[64];
            System.arraycopy(padded, i * 64, block, 0, 64);

            for (int j = 0; j < 16; j++) {
                W[j] = ((block[j*4] & 0xFF) << 24) |
                        ((block[j*4+1] & 0xFF) << 16) |
                        ((block[j*4+2] & 0xFF) << 8) |
                        (block[j*4+3] & 0xFF);
            }

            for (int j = 16; j < 80; j++) {
                W[j] = Integer.rotateLeft(W[j-3] ^ W[j-8] ^ W[j-14] ^ W[j-16], 1);
            }

            int A = H[0], B = H[1], C = H[2], D = H[3], E = H[4];

            for (int j = 0; j < 80; j++) {
                int f, k;
                if (j < 20) {
                    f = (B & C) | (~B & D);
                    k = 0x5A827999;
                } else if (j < 40) {
                    f = B ^ C ^ D;
                    k = 0x6ED9EBA1;
                } else if (j < 60) {
                    f = (B & C) | (B & D) | (C & D);
                    k = 0x8F1BBCDC;
                } else {
                    f = B ^ C ^ D;
                    k = 0xCA62C1D6;
                }

                int temp = Integer.rotateLeft(A, 5) + f + E + k + W[j];
                E = D;
                D = C;
                C = Integer.rotateLeft(B, 30);
                B = A;
                A = temp;
            }

            H[0] += A; H[1] += B; H[2] += C; H[3] += D; H[4] += E;
        }

        StringBuilder sb = new StringBuilder();
        for (int h : H) {
            sb.append(String.format("%08x", h));
        }
        return sb.toString();
    }

    private static byte[] padMessage(byte[] data) {
        int origLen = data.length;
        int tail = origLen % 64;
        int padLen = (tail < 56) ? (56 - tail) : (120 - tail);

        byte[] padded = new byte[origLen + padLen + 8];
        System.arraycopy(data, 0, padded, 0, origLen);
        padded[origLen] = (byte) 0x80;

        long bitLen = (long) origLen * 8;
        for (int i = 0; i < 8; i++) {
            padded[padded.length - 8 + i] = (byte) (bitLen >>> (56 - i * 8));
        }
        return padded;
    }
}
