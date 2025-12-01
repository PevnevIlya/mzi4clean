package com.example.AuthenticationService.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

@Service
public class StegoService {

    private static final int[] POS = {5, 6, 14, 15, 21, 22};

    public byte[] hide(MultipartFile file, String message) throws Exception {
        BufferedImage img = ImageIO.read(file.getInputStream());
        if (img == null) throw new IllegalArgumentException("Invalid image");
        if (img.getWidth() % 8 != 0 || img.getHeight() % 8 != 0)
            throw new IllegalArgumentException("Image dimensions must be multiple of 8");

        byte[] bytes = (message + "\0").getBytes(StandardCharsets.UTF_8);
        int[][][] dct = dctTransform(img);

        int bitIndex = 0;
        outer:
        for (int[][] blockRow : dct) {
            for (int[] block : blockRow) {
                for (int pos : POS) {
                    if (bitIndex >= bytes.length * 8) break outer;
                    int bit = (bytes[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1;
                    block[pos] = (block[pos] & ~1) | bit;
                    bitIndex++;
                }
            }
        }

        BufferedImage out = inverseDCT(dct, img.getWidth(), img.getHeight());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(out, "jpg", baos);
        return baos.toByteArray();
    }

    public String extract(MultipartFile file) throws Exception {
        BufferedImage img = ImageIO.read(file.getInputStream());
        if (img == null) throw new IllegalArgumentException("Invalid image");

        int[][][] dct = dctTransform(img);
        StringBuilder sb = new StringBuilder();
        byte b = 0;
        int count = 0;

        for (int[][] blockRow : dct) {
            for (int[] block : blockRow) {
                for (int pos : POS) {
                    int bit = block[pos] & 1;
                    b = (byte)((b << 1) | bit);
                    count++;
                    if (count == 8) {
                        if (b == 0) return sb.toString();
                        sb.append((char)(b & 0xFF));
                        b = 0;
                        count = 0;
                    }
                }
            }
        }
        return sb.toString();
    }

    private int[][][] dctTransform(BufferedImage img) {
        int w = img.getWidth() / 8;
        int h = img.getHeight() / 8;
        int[][][] result = new int[h][w][64];

        for (int by = 0; by < h; by++) {
            for (int bx = 0; bx < w; bx++) {
                int[] block = new int[64];
                for (int y = 0; y < 8; y++) {
                    for (int x = 0; x < 8; x++) {
                        int rgb = img.getRGB(bx*8 + x, by*8 + y);
                        int gray = (int)(0.299*((rgb>>16)&255) + 0.587*((rgb>>8)&255) + 0.114*(rgb&255));
                        block[y*8 + x] = gray - 128;
                    }
                }
                result[by][bx] = fdctAndQuantize(block);
            }
        }
        return result;
    }

    private int[] fdctAndQuantize(int[] block) {
        int[] coeff = new int[64];
        for (int v = 0; v < 8; v++) {
            for (int u = 0; u < 8; u++) {
                double sum = 0;
                for (int y = 0; y < 8; y++) {
                    for (int x = 0; x < 8; x++) {
                        sum += block[y*8 + x]
                                * Math.cos(Math.PI*u*(2*x+1)/16.0)
                                * Math.cos(Math.PI*v*(2*y+1)/16.0);
                    }
                }
                double c = (u==0 ? 1/Math.sqrt(2) : 1) * (v==0 ? 1/Math.sqrt(2) : 1);
                coeff[v*8 + u] = (int)Math.round(0.125 * c * sum);
            }
        }
        return coeff;
    }

    private BufferedImage inverseDCT(int[][][] blocks, int width, int height) {
        BufferedImage img = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        int bw = width / 8;
        int bh = height / 8;

        for (int by = 0; by < bh; by++) {
            for (int bx = 0; bx < bw; bx++) {
                int[] coeff = blocks[by][bx];
                int[] pixel = new int[64];
                for (int y = 0; y < 8; y++) {
                    for (int x = 0; x < 8; x++) {
                        double sum = 0;
                        for (int v = 0; v < 8; v++) {
                            for (int u = 0; u < 8; u++) {
                                double c = (u==0 ? 1/Math.sqrt(2) : 1) * (v==0 ? 1/Math.sqrt(2) : 1);
                                sum += c * coeff[v*8 + u]
                                        * Math.cos(Math.PI*u*(2*x+1)/16.0)
                                        * Math.cos(Math.PI*v*(2*y+1)/16.0);
                            }
                        }
                        pixel[y*8 + x] = (int)Math.round(sum * 0.125) + 128;
                    }
                }
                for (int y = 0; y < 8; y++) {
                    for (int x = 0; x < 8; x++) {
                        int p = pixel[y*8 + x];
                        p = Math.max(0, Math.min(255, p));
                        int rgb = p<<16 | p<<8 | p;
                        img.setRGB(bx*8 + x, by*8 + y, rgb);
                    }
                }
            }
        }
        return img;
    }
}