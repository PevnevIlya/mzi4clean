package com.example.AuthenticationService.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import javax.imageio.ImageIO;

@Service
public class StegoService {

    public byte[] hide(MultipartFile file, String message) throws Exception {
        BufferedImage img = ImageIO.read(file.getInputStream());
        byte[] bytes = (message + "\0").getBytes(StandardCharsets.UTF_8);

        int bit = 0;
        for (int y = 0; y < img.getHeight() && bit < bytes.length * 8; y++) {
            for (int x = 0; x < img.getWidth() && bit < bytes.length * 8; x++) {
                int rgb = img.getRGB(x, y);
                int alpha = rgb & 0xFF000000;
                int r = rgb & 0xFF;
                int needed = (bytes[bit / 8] >> (7 - bit % 8)) & 1;
                r = (r & 0xFE) | needed;
                img.setRGB(x, y, alpha | (r << 16) | ((rgb >> 8) & 0xFF00) | (rgb & 0xFF));
                bit++;
            }
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(img, "jpg", baos);
        return baos.toByteArray();
    }

    public String extract(MultipartFile file) throws Exception {
        BufferedImage img = ImageIO.read(file.getInputStream());
        StringBuilder sb = new StringBuilder();
        byte b = 0;
        int count = 0;

        for (int y = 0; y < img.getHeight(); y++) {
            for (int x = 0; x < img.getWidth(); x++) {
                int r = img.getRGB(x, y) & 0xFF;
                b = (byte)((b << 1) | (r & 1));
                count++;
                if (count == 8) {
                    if (b == 0) return sb.toString();
                    sb.append((char)(b & 0xFF));
                    b = 0;
                    count = 0;
                }
            }
        }
        return sb.toString();
    }
}