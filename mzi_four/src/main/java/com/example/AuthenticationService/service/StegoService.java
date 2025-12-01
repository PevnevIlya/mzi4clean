package com.example.AuthenticationService.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;
import javax.imageio.plugins.jpeg.JPEGImageWriteParam;

@Service
public class StegoService {

    public byte[] hide(MultipartFile file, String message) throws Exception {
        BufferedImage img = ImageIO.read(file.getInputStream());
        if (img == null) throw new IllegalArgumentException("Invalid image");

        byte[] msgBytes = (message + "\0").getBytes(StandardCharsets.UTF_8);
        int bitIndex = 0;

        // Прячем в красный канал (R)
        outer:
        for (int y = 0; y < img.getHeight(); y++) {
            for (int x = 0; x < img.getWidth(); x++) {
                if (bitIndex >= msgBytes.length * 8) break outer;

                int rgb = img.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int bit = (msgBytes[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1;
                r = (r & 0xFE) | bit;  // меняем только LSB

                int newRgb = (rgb & 0xFF00FFFF) | (r << 16);
                img.setRGB(x, y, newRgb);
                bitIndex++;
            }
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // КЛЮЧЕВОЕ: сохраняем JPEG БЕЗ СЖАТИЯ (качество 100%)
        ImageWriter writer = ImageIO.getImageWritersByFormatName("jpeg").next();
        JPEGImageWriteParam params = (JPEGImageWriteParam) writer.getDefaultWriteParam();
        params.setCompressionMode(JPEGImageWriteParam.MODE_EXPLICIT);
        params.setCompressionQuality(1.0f); // 100% качество — LSB сохраняется!

        try (ImageOutputStream ios = ImageIO.createImageOutputStream(baos)) {
            writer.setOutput(ios);
            writer.write(null, new javax.imageio.IIOImage(img, null, null), params);
        }
        writer.dispose();

        return baos.toByteArray();
    }

    public String extract(MultipartFile file) throws Exception {
        BufferedImage img = ImageIO.read(file.getInputStream());
        if (img == null) return "";

        StringBuilder sb = new StringBuilder();
        byte current = 0;
        int bits = 0;

        for (int y = 0; y < img.getHeight(); y++) {
            for (int x = 0; x < img.getWidth(); x++) {
                int r = (img.getRGB(x, y) >> 16) & 0xFF;
                int bit = r & 1;

                current = (byte) ((current << 1) | bit);
                bits++;

                if (bits == 8) {
                    if (current == 0) {
                        return sb.toString();
                    }
                    sb.append((char) (current & 0xFF));
                    current = 0;
                    bits = 0;
                }
            }
        }
        return sb.toString();
    }
}