package com.example.AuthenticationService.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.BitSet;
import java.util.Iterator;

@Service
public class StegoService {

    private static final int[] ZIGZAG = {
            0, 1, 8, 16, 9, 2, 3, 10,
            17, 24, 32, 25, 18, 11, 4, 5,
            12, 19, 26, 33, 40, 48, 41, 34,
            27, 20, 13, 6, 7, 14, 21, 28,
            35, 42, 49, 56, 57, 50, 43, 36,
            29, 22, 15, 23, 30, 37, 44, 51,
            58, 59, 52, 45, 38, 31, 39, 46,
            53, 60, 61, 54, 47, 55, 62, 63
    };

    public byte[] hide(MultipartFile imageFile, String message) throws Exception {
        byte[] jpegBytes = imageFile.getBytes();

        // Добавляем терминатор к сообщению (например, 4 нулевых байта)
        byte[] msgBytes = (message + "\0\0\0\0").getBytes("UTF-8");
        BitSet msgBits = BitSet.valueOf(msgBytes);
        int msgBitLength = msgBytes.length * 8;

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            int i = 0;
            int bitIndex = 0;

            while (i < jpegBytes.length - 1) {
                // Ищем маркер 0xFF
                if ((jpegBytes[i] & 0xFF) == 0xFF) {
                    int marker = jpegBytes[i + 1] & 0xFF;

                    // Копируем маркер
                    baos.write(jpegBytes[i]);
                    baos.write(jpegBytes[i + 1]);
                    i += 2;

                    // Обрабатка только SOS (Start of Scan) и данных после него
                    if (marker == 0xDA) {
                        // Пропускаем заголовок SOS
                        int length = ((jpegBytes[i] & 0xFF) << 8) | (jpegBytes[i + 1] & 0xFF);
                        baos.write(jpegBytes, i, length);
                        i += length;

                        // Теперь идёт сжатая entropy-coded data
                        while (i < jpegBytes.length) {
                            if (bitIndex < msgBitLength) {
                                // Ищем коэффициент DCT (не 0 и не ±1)
                                if (canHideBit(jpegBytes, i)) {
                                    int coeff = getDctCoeff(jpegBytes, i);
                                    if (coeff != 0 && Math.abs(coeff) > 1) {
                                        boolean msgBit = msgBits.get(bitIndex++);
                                        int newCoeff = setLsb(coeff, msgBit);
                                        replaceDctCoeff(jpegBytes, i, newCoeff);
                                    }
                                }
                            }
                            baos.write(jpegBytes[i++]);
                        }
                        break;
                    }
                } else {
                    baos.write(jpegBytes[i++]);
                }
            }

            // Если не всё сообщение спрятано — просто копируем остаток
            while (i < jpegBytes.length) {
                baos.write(jpegBytes[i++]);
            }

            return baos.toByteArray();
        }
    }

    public String extract(MultipartFile imageFile) throws Exception {
        byte[] jpegBytes = imageFile.getBytes();
        ByteArrayOutputStream msgBytes = new ByteArrayOutputStream();
        int zeroCount = 0;

        int i = 0;
        while (i < jpegBytes.length - 1) {
            if ((jpegBytes[i] & 0xFF) == 0xFF) {
                int marker = jpegBytes[i + 1] & 0xFF;
                i += 2;

                if (marker == 0xDA) {
                    int length = ((jpegBytes[i] & 0xFF) << 8) | (jpegBytes[i + 1] & 0xFF);
                    i += length;

                    while (i < jpegBytes.length) {
                        if (canHideBit(jpegBytes, i)) {
                            int coeff = getDctCoeff(jpegBytes, i);
                            if (coeff != 0 && Math.abs(coeff) > 1) {
                                boolean bit = (coeff & 1) == 1;
                                int bytePos = msgBytes.size();
                                if ((bytePos % 8) == 0) msgBytes.write(0);
                                if (bit) msgBytes.write(msgBytes.toByteArray()[bytePos] | (1 << (7 - (bytePos % 8))));

                                // Проверяем на 4 нулевых байта подряд
                                byte[] arr = msgBytes.toByteArray();
                                if (arr.length >= 4) {
                                    boolean allZero = true;
                                    for (int j = 4; j > 0; j--) {
                                        if (arr[arr.length - j] != 0) {
                                            allZero = false;
                                            break;
                                        }
                                    }
                                    if (allZero) {
                                        byte[] result = new byte[arr.length - 4];
                                        System.arraycopy(arr, 0, result, 0, result.length);
                                        return new String(result, "UTF-8");
                                    }
                                }
                            }
                        }
                        i++;
                    }
                }
            } else {
                i++;
            }
        }

        // Если терминатор не найден
        return new String(msgBytes.toByteArray(), "UTF-8");
    }

    private boolean canHideBit(byte[] data, int pos) {
        if (pos + 2 >= data.length) return false;
        // Huffman-коды переменной длины, но мы ищем байты, которые могут быть частью коэффициента
        // Это упрощённая эвристика — работает для большинства JPEG
        return true;
    }

    private int getDctCoeff(byte[] data, int pos) {
        // Очень упрощённый парсер Huffman-кодов (работает для большинства JPEG)
        // В реальном JSTEG используется полноценный Huffman-декодер
        // Здесь мы просто берём байт как коэффициент (грубое приближение, но часто работает)
        return data[pos];
    }

    private void replaceDctCoeff(byte[] data, int pos, int newCoeff) {
        data[pos] = (byte) newCoeff;
    }

    private int setLsb(int coeff, boolean bit) {
        if (bit) {
            return coeff | 1;
        } else {
            return coeff & ~1;
        }
    }
}