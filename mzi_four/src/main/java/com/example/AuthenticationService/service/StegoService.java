package com.example.AuthenticationService.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

@Service
public class StegoService {

    private static final int[] COEFFS = {1, 2, 5};

    public byte[] hideMessage(MultipartFile file, String message) throws Exception {
        BufferedImage img = ImageIO.read(file.getInputStream());
        if (img == null) throw new IllegalArgumentException("Invalid image");

        byte[] data = (message + "\0").getBytes(StandardCharsets.UTF_8);
        float[][][] dct = forwardDCT(img);
        embedData(dct, data);
        BufferedImage out = inverseDCT(dct, img.getWidth(), img.getHeight());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(out, "jpg", baos);
        return baos.toByteArray();
    }

    public String extractMessage(MultipartFile file) throws Exception {
        BufferedImage img = ImageIO.read(file.getInputStream());
        if (img == null) throw new IllegalArgumentException("Invalid image");

        float[][][] dct = forwardDCT(img);
        StringBuilder sb = new StringBuilder();
        byte current = 0;
        int count = 0;

        for (float[][] row : dct) {
            for (float[] block : row) {
                for (int i : COEFFS) {
                    if (i >= block.length) continue;
                    float c = block[i];
                    int bit = ((int)c & 1);
                    if (c < 0) bit = 1 - bit;
                    current = (byte)((current << 1) | bit);
                    count++;
                    if (count == 8) {
                        if (current == 0) return sb.toString();
                        sb.append((char)(current & 0xFF));
                        current = 0;
                        count = 0;
                    }
                }
            }
        }
        return sb.toString();
    }

    private float[][][] forwardDCT(BufferedImage img) {
        int w = img.getWidth();
        int h = img.getHeight();
        int bw = w / 8;
        int bh = h / 8;
        float[][][] blocks = new float[bh][bw][64];

        for (int by = 0; by < bh; by++) {
            for (int bx = 0; bx < bw; bx++) {
                float[][] block = new float[8][8];
                for (int y = 0; y < 8; y++) {
                    for (int x = 0; x < 8; x++) {
                        int rgb = img.getRGB(bx*8 + x, by*8 + y);
                        int gray = (int)(0.299*((rgb>>16)&255) + 0.587*((rgb>>8)&255) + 0.114*(rgb&255));
                        block[y][x] = gray - 128f;
                    }
                }
                blocks[by][bx] = dctBlock(block);
            }
        }
        return blocks;
    }

    private float[] dctBlock(float[][] block) {
        float[] dct = new float[64];
        for (int u = 0; u < 8; u++) {
            for (int v = 0; v < 8; v++) {
                float sum = 0f;
                for (int x = 0; x < 8; x++) {
                    for (int y = 0; y < 8; y++) {
                        sum += block[y][x]
                                * Math.cos(Math.PI * u * (2*x + 1) / 16)
                                * Math.cos(Math.PI * v * (2*y + 1) / 16);
                    }
                }
                float cu = u == 0 ? 0.70710677f : 1f;
                float cv = v == 0 ? 0.70710677f : 1f;
                dct[v*8 + u] = 0.25f * cu * cv * sum;
            }
        }
        return dct;
    }

    private void embedData(float[][][] blocks, byte[] data) {
        int bit = 0;
        for (float[][] row : blocks) {
            for (float[] block : row) {
                if (bit >= data.length * 8) return;
                for (int i : COEFFS) {
                    if (bit >= data.length * 8 || i >= block.length) break;
                    int neededBit = (data[bit/8] >> (7 - bit%8)) & 1;
                    float c = block[i];
                    int currentBit = ((int)c & 1);
                    if (c < 0) currentBit = 1 - currentBit;
                    if (currentBit != neededBit) {
                        c = c >= 0 ? c + (neededBit == 1 ? 1 : -1) : c + (neededBit == 1 ? -1 : 1);
                    }
                    block[i] = c;
                    bit++;
                }
            }
        }
    }

    private BufferedImage inverseDCT(float[][][] blocks, int width, int height) {
        BufferedImage img = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        for (int by = 0; by < blocks.length; by++) {
            for (int bx = 0; bx < blocks[by].length; bx++) {
                float[][] block = idctBlock(blocks[by][bx]);
                for (int y = 0; y < 8; y++) {
                    for (int x = 0; x < 8; x++) {
                        int p = Math.round(block[y][x] + 128f);
                        p = Math.max(0, Math.min(255, p));
                        int rgb = p<<16 | p<<8 | p;
                        img.setRGB(bx*8 + x, by*8 + y, rgb);
                    }
                }
            }
        }
        return img;
    }

    private float[][] idctBlock(float[] dct) {
        float[][] block = new float[8][8];
        for (int x = 0; x < 8; x++) {
            for (int y = 0; y < 8; y++) {
                float sum = 0f;
                for (int u = 0; u < 8; u++) {
                    for (int v = 0; v < 8; v++) {
                        float cu = u == 0 ? 0.70710677f : 1f;
                        float cv = v == 0 ? 0.70710677f : 1f;
                        sum += cu * cv * dct[v*8 + u]
                                * Math.cos(Math.PI * u * (2*x + 1) / 16)
                                * Math.cos(Math.PI * v * (2*y + 1) / 16);
                    }
                }
                block[y][x] = 0.25f * sum;
            }
        }
        return block;
    }
}