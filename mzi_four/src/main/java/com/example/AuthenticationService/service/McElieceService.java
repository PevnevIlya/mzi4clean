package com.example.AuthenticationService.service;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.Arrays;

@Service
public class McElieceService {
    private final int n = 16;
    private final int k = 8;
    private final int t = 2;

    private final boolean[][] G;
    private final boolean[][] P;
    private final boolean[][] S;
    private final boolean[][] G1;

    private final Random rnd = new Random(12345);

    public McElieceService() {
        G = randomGeneratorMatrix(k, n);
        S = randomInvertibleMatrix(k);
        int[] perm = randomPermutation(n);
        P = permutationMatrixFromPerm(perm);
        G1 = multiply(multiply(S, G), P);
    }

    public String encryptText(String text) {
        byte[] utf = text.getBytes(StandardCharsets.UTF_8);
        String b64 = Base64.getEncoder().encodeToString(utf);
        byte[] b64bytes = b64.getBytes(StandardCharsets.UTF_8);
        int len = b64bytes.length;
        byte[] payload = new byte[4 + len];
        payload[0] = (byte) ((len >>> 24) & 0xFF);
        payload[1] = (byte) ((len >>> 16) & 0xFF);
        payload[2] = (byte) ((len >>> 8) & 0xFF);
        payload[3] = (byte) (len & 0xFF);
        System.arraycopy(b64bytes, 0, payload, 4, len);
        boolean[] bits = bytesToBits(payload);
        List<boolean[]> codewords = new ArrayList<>();
        int pos = 0;
        while (pos < bits.length) {
            boolean[] m = new boolean[k];
            for (int i = 0; i < k; i++) {
                m[i] = (pos < bits.length) && bits[pos];
                pos++;
            }
            boolean[] cw = encodeBlock(m);
            codewords.add(cw);
        }
        boolean[] all = concat(codewords);
        byte[] out = bitsToBytes(all);
        return Base64.getEncoder().encodeToString(out);
    }

    public String decryptCipher(String base64cipher) {
        byte[] raw = Base64.getDecoder().decode(base64cipher);
        boolean[] bits = bytesToBits(raw);
        int pos = 0;
        List<boolean[]> messages = new ArrayList<>();
        while (pos + n <= bits.length) {
            boolean[] cw = new boolean[n];
            for (int i = 0; i < n; i++) cw[i] = bits[pos++];
            boolean[] m = decodeBlock(cw);
            messages.add(m);
        }
        boolean[] all = concat(messages);
        byte[] out = bitsToBytes(all);
        byte[] trimmed = trimTrailingZeros(out);
        if (trimmed.length < 4) return "";
        int len = ((trimmed[0] & 0xFF) << 24) | ((trimmed[1] & 0xFF) << 16) | ((trimmed[2] & 0xFF) << 8) | (trimmed[3] & 0xFF);
        if (len <= 0 || len > trimmed.length - 4) return "";
        byte[] b64bytes = Arrays.copyOfRange(trimmed, 4, 4 + len);
        byte[] original;
        try {
            original = Base64.getDecoder().decode(b64bytes);
        } catch (IllegalArgumentException e) {
            return "";
        }
        return new String(original, StandardCharsets.UTF_8);
    }

    private boolean[] encodeBlock(boolean[] m) {
        boolean[] c = new boolean[n];
        for (int j = 0; j < n; j++) {
            boolean bit = false;
            for (int i = 0; i < k; i++) bit ^= (m[i] & G1[i][j]);
            c[j] = bit;
        }
        return c;
    }

    private boolean[] decodeBlock(boolean[] cw) {
        int limit = 1 << k;
        for (int mval = 0; mval < limit; mval++) {
            boolean[] m = intToBits(mval, k);
            boolean[] expect = encodeBlock(m);
            int dist = hammingDistance(expect, cw);
            if (dist == 0) return m;
        }
        return new boolean[k];
    }

    private boolean[][] randomGeneratorMatrix(int rows, int cols) {
        boolean[][] a = new boolean[rows][cols];
        for (int i = 0; i < rows; i++)
            for (int j = 0; j < cols; j++)
                a[i][j] = rnd.nextBoolean();
        return a;
    }

    private boolean[][] randomInvertibleMatrix(int size) {
        boolean[][] mtx;
        do {
            mtx = new boolean[size][size];
            for (int i = 0; i < size; i++)
                for (int j = 0; j < size; j++)
                    mtx[i][j] = rnd.nextBoolean();
        } while (rank(mtx) < size);
        return mtx;
    }

    private int[] randomPermutation(int n) {
        int[] a = new int[n];
        for (int i = 0; i < n; i++) a[i] = i;
        for (int i = n - 1; i > 0; i--) {
            int j = rnd.nextInt(i + 1);
            int t = a[i]; a[i] = a[j]; a[j] = t;
        }
        return a;
    }

    private boolean[][] permutationMatrixFromPerm(int[] perm) {
        int n = perm.length;
        boolean[][] m = new boolean[n][n];
        for (int i = 0; i < n; i++) m[i][perm[i]] = true;
        return m;
    }

    private boolean[][] multiply(boolean[][] A, boolean[][] B) {
        int r = A.length;
        int m = A[0].length;
        int c = B[0].length;
        boolean[][] C = new boolean[r][c];
        for (int i = 0; i < r; i++)
            for (int j = 0; j < c; j++) {
                boolean s = false;
                for (int p = 0; p < m; p++) s ^= (A[i][p] & B[p][j]);
                C[i][j] = s;
            }
        return C;
    }

    private int rank(boolean[][] mat) {
        int rows = mat.length;
        int cols = mat[0].length;
        boolean[][] a = new boolean[rows][cols];
        for (int i = 0; i < rows; i++) System.arraycopy(mat[i], 0, a[i], 0, cols);
        int rank = 0;
        for (int col = 0; col < cols && rank < rows; col++) {
            int sel = -1;
            for (int i = rank; i < rows; i++) if (a[i][col]) { sel = i; break; }
            if (sel == -1) continue;
            boolean[] tmp = a[rank]; a[rank] = a[sel]; a[sel] = tmp;
            for (int i = 0; i < rows; i++) if (i != rank && a[i][col]) {
                for (int j = col; j < cols; j++) a[i][j] ^= a[rank][j];
            }
            rank++;
        }
        return rank;
    }

    private boolean[] randomErrorVector(int n, int maxWeight) {
        boolean[] v = new boolean[n];
        int w = rnd.nextInt(maxWeight + 1);
        for (int i = 0; i < w; i++) {
            int pos;
            do { pos = rnd.nextInt(n); } while (v[pos]);
            v[pos] = true;
        }
        return v;
    }

    private boolean[] xor(boolean[] a, boolean[] b) {
        boolean[] r = new boolean[a.length];
        for (int i = 0; i < a.length; i++) r[i] = a[i] ^ b[i];
        return r;
    }

    private boolean[] concat(List<boolean[]> blocks) {
        int total = blocks.stream().mapToInt(b -> b.length).sum();
        boolean[] out = new boolean[total];
        int p = 0;
        for (boolean[] b : blocks) {
            System.arraycopy(b, 0, out, p, b.length);
            p += b.length;
        }
        return out;
    }

    private boolean[] bytesToBits(byte[] data) {
        boolean[] bits = new boolean[data.length * 8];
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xFF;
            for (int b = 0; b < 8; b++) bits[i * 8 + b] = ((v >> (7 - b)) & 1) == 1;
        }
        return bits;
    }

    private byte[] bitsToBytes(boolean[] bits) {
        int len = (bits.length + 7) / 8;
        byte[] out = new byte[len];
        for (int i = 0; i < bits.length; i++) {
            if (bits[i]) out[i / 8] |= (1 << (7 - (i % 8)));
        }
        return out;
    }

    private boolean[] intToBits(int v, int bits) {
        boolean[] r = new boolean[bits];
        for (int i = 0; i < bits; i++) r[bits - 1 - i] = ((v >> i) & 1) == 1;
        return r;
    }

    private int hammingDistance(boolean[] a, boolean[] b) {
        int d = 0;
        for (int i = 0; i < a.length; i++) if (a[i] != b[i]) d++;
        return d;
    }

    private byte[] trimTrailingZeros(byte[] arr) {
        int last = arr.length;
        while (last > 0 && arr[last - 1] == 0) last--;
        return Arrays.copyOf(arr, last);
    }
}
