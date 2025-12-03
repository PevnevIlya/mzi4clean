package com.example.AuthenticationService.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.MemoryCacheImageOutputStream;
import java.awt.image.BufferedImage;
import java.awt.image.WritableRaster;
import java.io.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Iterator;

@Service
public class StegoServiceImpl implements StegoService {

    private static final int BLOCK = 8;
    // Zig-zag order for 8x8
    private static final int[] ZIGZAG = {
            0,1,8,16,9,2,3,10,
            17,24,32,25,18,11,4,5,
            12,19,26,33,40,48,41,34,
            27,20,13,6,7,14,21,28,
            35,42,49,56,57,50,43,36,
            29,22,15,23,30,37,44,51,
            58,59,52,45,38,31,39,46,
            53,60,61,54,47,55,62,63
    };

    @Override
    public byte[] hide(MultipartFile image, String message) throws Exception {
        BufferedImage src = ImageIO.read(image.getInputStream());
        if (src == null) throw new IllegalArgumentException("Invalid image file");

        int width = src.getWidth();
        int height = src.getHeight();

        // Make width and height multiples of 8 by padding if necessary
        int paddedW = (width + BLOCK - 1) / BLOCK * BLOCK;
        int paddedH = (height + BLOCK - 1) / BLOCK * BLOCK;

        // Convert RGB -> YCbCr arrays
        double[][] Y = new double[paddedH][paddedW];
        double[][] Cb = new double[paddedH][paddedW];
        double[][] Cr = new double[paddedH][paddedW];

        // Fill using nearest padding
        for (int y = 0; y < paddedH; y++) {
            for (int x = 0; x < paddedW; x++) {
                int sx = Math.min(x, width - 1);
                int sy = Math.min(y, height - 1);
                int rgb = src.getRGB(sx, sy);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;
                // Convert to YCbCr (BT.601)
                double yy =  0.299 * r + 0.587 * g + 0.114 * b;
                double cb = -0.168736 * r - 0.331264 * g + 0.5 * b + 128;
                double cr =  0.5 * r - 0.418688 * g - 0.081312 * b + 128;
                Y[y][x] = yy;
                Cb[y][x] = cb;
                Cr[y][x] = cr;
            }
        }

        // Prepare bitstream: 4 bytes length + UTF-8 bytes
        byte[] msgBytes = message.getBytes("UTF-8");
        int msgLen = msgBytes.length;
        ByteBuffer bb = ByteBuffer.allocate(4 + msgLen);
        bb.putInt(msgLen);
        bb.put(msgBytes);
        byte[] payload = bb.array();
        boolean[] bits = bytesToBits(payload);

        // Capacity: one bit per block (if we embed one bit per block), or more if we find multiple AC coefficients
        // Here we will embed ONE bit per block using the first suitable AC coefficient found in zigzag order.
        int blocksX = paddedW / BLOCK;
        int blocksY = paddedH / BLOCK;
        int capacity = blocksX * blocksY; // one bit per block
        if (bits.length > capacity) {
            throw new IllegalArgumentException("Message too big for image. Capacity (bits): " + capacity + ", required: " + bits.length);
        }

        // Process blocks: DCT, embed, IDCT
        for (int by = 0, bitIndex = 0; by < blocksY; by++) {
            for (int bx = 0; bx < blocksX; bx++) {
                // Extract 8x8 block
                double[][] block = new double[BLOCK][BLOCK];
                for (int v = 0; v < BLOCK; v++) {
                    for (int u = 0; u < BLOCK; u++) {
                        block[v][u] = Y[by * BLOCK + v][bx * BLOCK + u] - 128.0; // shift
                    }
                }
                // DCT
                double[][] coeff = dct2(block);

                // Find coefficient to embed (skip DC at (0,0))
                int embedPos = findEmbeddingIndex(coeff);
                if (embedPos >= 0 && bitIndex < bits.length) {
                    int zz = ZIGZAG[embedPos]; // 0..63
                    int row = zz / BLOCK;
                    int col = zz % BLOCK;
                    // modify coefficient's integer LSB
                    int rounded = (int) Math.round(coeff[row][col]);
                    int bit = bits[bitIndex] ? 1 : 0;
                    rounded = (rounded & ~1) | bit;
                    coeff[row][col] = rounded;
                    bitIndex++;
                } else {
                    // no suitable AC coefficient found -> leave block unchanged
                }

                // IDCT
                double[][] id = idct2(coeff);
                // Place back (clamp)
                for (int v = 0; v < BLOCK; v++) {
                    for (int u = 0; u < BLOCK; u++) {
                        double val = id[v][u] + 128.0;
                        val = Math.max(0, Math.min(255, val));
                        Y[by * BLOCK + v][bx * BLOCK + u] = val;
                    }
                }
            }
        }

        // Recombine YCbCr -> RGB and write BufferedImage
        BufferedImage out = new BufferedImage(paddedW, paddedH, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < paddedH; y++) {
            for (int x = 0; x < paddedW; x++) {
                // Use original CbCr values (we kept them)
                double yy = Y[y][x];
                double cb = Cb[y][x] - 128;
                double cr = Cr[y][x] - 128;
                int r = (int) Math.round(yy + 1.402 * cr);
                int g = (int) Math.round(yy - 0.344136 * cb - 0.714136 * cr);
                int b = (int) Math.round(yy + 1.772 * cb);
                r = clamp(r);
                g = clamp(g);
                b = clamp(b);
                int rgb = (r << 16) | (g << 8) | b;
                out.setRGB(x, y, rgb);
            }
        }

        // Crop back to original width/height if padded
        BufferedImage finalImg = out.getSubimage(0, 0, width, height);

        // Write to JPEG in-memory with high quality
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Iterator<ImageWriter> writers = ImageIO.getImageWritersByFormatName("jpg");
        if (!writers.hasNext()) throw new IllegalStateException("No JPEG writer found");
        ImageWriter writer = writers.next();
        ImageWriteParam jpgParams = writer.getDefaultWriteParam();
        jpgParams.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
        jpgParams.setCompressionQuality(0.95f);

        MemoryCacheImageOutputStream ios = new MemoryCacheImageOutputStream(baos);
        writer.setOutput(ios);
        writer.write(null, new IIOImage(finalImg, null, null), jpgParams);
        ios.close();
        writer.dispose();

        return baos.toByteArray();
    }

    @Override
    public String extract(MultipartFile image) throws Exception {
        BufferedImage src = ImageIO.read(image.getInputStream());
        if (src == null) throw new IllegalArgumentException("Invalid image file");

        int width = src.getWidth();
        int height = src.getHeight();

        int paddedW = (width + BLOCK - 1) / BLOCK * BLOCK;
        int paddedH = (height + BLOCK - 1) / BLOCK * BLOCK;

        double[][] Y = new double[paddedH][paddedW];
        double[][] Cb = new double[paddedH][paddedW];
        double[][] Cr = new double[paddedH][paddedW];

        for (int y = 0; y < paddedH; y++) {
            for (int x = 0; x < paddedW; x++) {
                int sx = Math.min(x, width - 1);
                int sy = Math.min(y, height - 1);
                int rgb = src.getRGB(sx, sy);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;
                double yy =  0.299 * r + 0.587 * g + 0.114 * b;
                double cb = -0.168736 * r - 0.331264 * g + 0.5 * b + 128;
                double cr =  0.5 * r - 0.418688 * g - 0.081312 * b + 128;
                Y[y][x] = yy;
                Cb[y][x] = cb;
                Cr[y][x] = cr;
            }
        }

        int blocksX = paddedW / BLOCK;
        int blocksY = paddedH / BLOCK;

        // We'll read bits in same order: one bit per block
        // First 32 bits => message length in bytes
        int headerBits = 32;
        boolean[] bitsCollected = new boolean[blocksX * blocksY];
        int bIdx = 0;
        for (int by = 0; by < blocksY; by++) {
            for (int bx = 0; bx < blocksX; bx++) {
                double[][] block = new double[BLOCK][BLOCK];
                for (int v = 0; v < BLOCK; v++) {
                    for (int u = 0; u < BLOCK; u++) {
                        block[v][u] = Y[by * BLOCK + v][bx * BLOCK + u] - 128.0;
                    }
                }
                double[][] coeff = dct2(block);
                int embedPos = findEmbeddingIndex(coeff);
                boolean bit = false;
                if (embedPos >= 0) {
                    int zz = ZIGZAG[embedPos];
                    int row = zz / BLOCK;
                    int col = zz % BLOCK;
                    int rounded = (int) Math.round(coeff[row][col]);
                    bit = (rounded & 1) == 1;
                }
                bitsCollected[bIdx++] = bit;
            }
        }

        // Convert bits to bytes
        // First read 32-bit length
        if (bitsCollected.length < headerBits) return "";
        byte[] headerBytes = bitsToBytes(Arrays.copyOfRange(bitsCollected, 0, headerBits));
        int msgLen = ByteBuffer.wrap(headerBytes).getInt();
        if (msgLen < 0 || msgLen > (blocksX * blocksY) / 8) {
            // suspicious -> probably no message
            return "";
        }

        int totalBitsNeeded = (4 + msgLen) * 8;
        if (totalBitsNeeded > bitsCollected.length) {
            // message truncated
            return "";
        }
        boolean[] payloadBits = Arrays.copyOfRange(bitsCollected, 0, totalBitsNeeded);
        byte[] payload = bitsToBytes(payloadBits);
        // first 4 bytes are length
        byte[] msgBytes = Arrays.copyOfRange(payload, 4, 4 + msgLen);
        return new String(msgBytes, "UTF-8");
    }

    // Helpers

    private static int clamp(int v) {
        if (v < 0) return 0;
        if (v > 255) return 255;
        return v;
    }

    // find first suitable AC coeff index in zigzag order (skip DC at pos 0 and very low freq positions)
    private int findEmbeddingIndex(double[][] coeff) {
        // Start scanning zigzag from position 1 upwards and skip very-low frequency (positions 1..3) optionally,
        // but for simplicity we start at pos=1
        for (int pos = 1; pos < ZIGZAG.length; pos++) {
            int zz = ZIGZAG[pos];
            int row = zz / BLOCK;
            int col = zz % BLOCK;
            // prefer coefficients with non-zero magnitude (so change LSB won't be trivially destroyed by quantization)
            if (Math.abs(coeff[row][col]) >= 0.5) {
                return pos;
            }
        }
        // if none found, still return the first AC (pos=1) to ensure capacity (even if zero)
        return 1;
    }

    // DCT type-II 8x8
    private double[][] dct2(double[][] block) {
        int N = BLOCK;
        double[][] temp = new double[N][N];
        double[][] out = new double[N][N];

        // 1D DCT on rows
        for (int i = 0; i < N; i++) {
            temp[i] = dct1D(block[i]);
        }
        // 1D DCT on columns
        for (int j = 0; j < N; j++) {
            double[] col = new double[N];
            for (int i = 0; i < N; i++) col[i] = temp[i][j];
            double[] colDct = dct1D(col);
            for (int i = 0; i < N; i++) out[i][j] = colDct[i];
        }
        return out;
    }

    // IDCT (inverse)
    private double[][] idct2(double[][] block) {
        int N = BLOCK;
        double[][] temp = new double[N][N];
        double[][] out = new double[N][N];

        // 1D IDCT on columns (apply idct1D to each column)
        for (int j = 0; j < N; j++) {
            double[] col = new double[N];
            for (int i = 0; i < N; i++) col[i] = block[i][j];
            double[] colIdct = idct1D(col);
            for (int i = 0; i < N; i++) temp[i][j] = colIdct[i];
        }
        // 1D IDCT on rows
        for (int i = 0; i < N; i++) {
            double[] rowIdct = idct1D(temp[i]);
            for (int j = 0; j < N; j++) out[i][j] = rowIdct[j];
        }
        return out;
    }

    // 1D DCT-II
    private double[] dct1D(double[] data) {
        int N = data.length;
        double[] result = new double[N];
        double factor = Math.PI / (2.0 * N);
        for (int k = 0; k < N; k++) {
            double sum = 0;
            for (int n = 0; n < N; n++) {
                sum += data[n] * Math.cos((2.0 * n + 1) * k * factor);
            }
            double ck = (k == 0) ? Math.sqrt(1.0 / N) : Math.sqrt(2.0 / N);
            result[k] = ck * sum;
        }
        return result;
    }

    // 1D IDCT (inverse of above)
    private double[] idct1D(double[] data) {
        int N = data.length;
        double[] result = new double[N];
        double factor = Math.PI / (2.0 * N);
        for (int n = 0; n < N; n++) {
            double sum = 0;
            for (int k = 0; k < N; k++) {
                double ck = (k == 0) ? Math.sqrt(1.0 / N) : Math.sqrt(2.0 / N);
                sum += ck * data[k] * Math.cos((2.0 * n + 1) * k * factor);
            }
            result[n] = sum;
        }
        return result;
    }

    // Convert byte[] -> bit boolean[]
    private boolean[] bytesToBits(byte[] data) {
        boolean[] bits = new boolean[data.length * 8];
        for (int i = 0; i < data.length; i++) {
            for (int b = 0; b < 8; b++) {
                bits[i * 8 + b] = ((data[i] >> (7 - b)) & 1) == 1;
            }
        }
        return bits;
    }

    // Convert boolean[] bits -> byte[]
    private byte[] bitsToBytes(boolean[] bits) {
        int bytes = bits.length / 8;
        byte[] out = new byte[bytes];
        for (int i = 0; i < bytes; i++) {
            int val = 0;
            for (int b = 0; b < 8; b++) {
                if (bits[i * 8 + b]) val |= 1 << (7 - b);
            }
            out[i] = (byte) val;
        }
        return out;
    }
}
