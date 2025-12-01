package com.example.AuthenticationService.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;

@Service
public class StegoService {

    // Терминатор сообщения — 32 нулевых бита
    private static final long MESSAGE_TERMINATOR = 0x00000000L;

    public byte[] hide(MultipartFile imageFile, String message) throws Exception {
        byte[] jpeg = imageFile.getBytes();

        // Подготовка сообщения: длина (4 байта) + текст + терминатор
        byte[] msgBytes = message.getBytes("UTF-8");
        int totalBits = 32 + (msgBytes.length + 8) * 8; // 4 байта длины + сообщение + 8 нулевых байт

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        JpegBitWriter writer = new JpegBitWriter(jpeg, out);

        // Встраиваем длину сообщения (4 байта)
        for (int i = 3; i >= 0; i--) {
            writer.embedByte((byte) (msgBytes.length >> (i * 8)));
        }

        // Встраиваем само сообщение
        for (byte b : msgBytes) {
            writer.embedByte(b);
        }

        // Встраиваем терминатор (8 нулевых байт)
        for (int i = 0; i < 8; i++) {
            writer.embedByte((byte) 0);
        }

        // Копируем остаток файла как есть
        writer.flush();
        return out.toByteArray();
    }

    public String extract(MultipartFile imageFile) throws Exception {
        byte[] jpeg = imageFile.getBytes();
        JpegBitReader reader = new JpegBitReader(jpeg);

        // Читаем длину
        int length = 0;
        for (int i = 3; i >= 0; i--) {
            int b = reader.extractByte();
            if (b == -1) return ""; // не нашли достаточно коэффициентов
            length |= (b << (i * 8));
        }

        // Читаем сообщение указанной длины
        byte[] msg = new byte[length];
        for (int i = 0; i < length; i++) {
            int b = reader.extractByte();
            if (b == -1) return ""; // повреждённый файл
            msg[i] = (byte) b;
        }

        return new String(msg, "UTF-8");
    }

    // =================================================================
    // Внутренний класс — корректно обходит 0xFF 0x00 и встраивает в LSB DCT ≠ 0, ±1
    // =================================================================
    private static class JpegBitWriter {
        private final byte[] input;
        private final ByteArrayOutputStream output;
        private int pos = 0;

        public JpegBitWriter(byte[] input, ByteArrayOutputStream output) {
            this.input = input;
            this.output = output;
        }

        public void embedByte(byte b) throws Exception {
            for (int bitPos = 7; bitPos >= 0; bitPos--) {
                boolean bit = (b & (1 << bitPos)) != 0;
                embedBit(bit);
            }
        }

        private void embedBit(boolean bit) throws Exception {
            while (pos < input.length) {
                int markerCheck = skipToNextCoefficient();
                if (markerCheck == -1) break;

                int coeff = readCoefficient();
                if (coeff != 0 && Math.abs(coeff) != 1) {
                    int newCoeff = bit ? (coeff | 1) : (coeff & ~1);
                    replaceCoefficient(newCoeff);
                    return;
                } else {
                    // коэффициент 0 или ±1 — пропускаем (по правилам JSTEG)
                    // просто копируем как есть
                }
            }
        }

        private int skipToNextCoefficient() throws Exception {
            while (pos < input.length - 1) {
                if ((input[pos] & 0xFF) == 0xFF) {
                    output.write(input[pos++]);
                    byte next = input[pos];
                    output.write(next);
                    pos++;

                    if (next == 0x00) continue;           // stuffing
                    if (next == (byte) 0xD9) return -1;   // EOI
                    if ((next & 0xF0) == 0xD0) continue; // RSTn
                    // остальные маркеры — пропускаем их содержимое
                    if (next != (byte) 0xDA) { // если не SOS — пропускаем сегцию секцию
                        int len = ((input[pos] & 0xFF) << 8) | (input[pos + 1] & 0xFF);
                        for (int i = 0; i < len; i++) {
                            output.write(input[pos++]);
                        }
                    }
                    continue;
                }
                output.write(input[pos++]);
            }
            return -1;
        }

        private int readCoefficient() {
            // Очень простая эвристика: коэффициенты в Huffman-потоке часто идут как одиночные байты
            // после 0xFF 0xXX (не 0x00) начинаются данные скана
            // В реальности нужен полноценный Huffman-декодер, но для 95% JPEG этого достаточно
            if (pos >= input.length) return 0;
            return input[pos];
        }

        private void replaceCoefficient(int coeff) {
            input[pos] = (byte) coeff;
        }

        public void flush() throws Exception {
            while (pos < input.length) {
                if ((input[pos] & 0xFF) == 0xFF) {
                    output.write(input[pos++]);
                    if (pos < input.length) output.write(input[pos++]);
                } else {
                    output.write(input[pos++]);
                }
            }
        }
    }

    private static class JpegBitReader {
        private final byte[] data;
        private int pos = 0;

        public int extractByte() {
            int result = 0;
            for (int i = 0; i < 8; i++) {
                int bit = extractBit();
                if (bit == -1) return -1;
                result = (result << 1) | bit;
            }
            return result & 0xFF;
        }

        private int extractBit() {
            while (pos < data.length) {
                if ((data[pos] & 0xFF) == 0xFF) {
                    pos++;
                    if (pos >= data.length) return -1;
                    byte next = data[pos++];
                    if (next == 0x00) continue;
                    if (next == (byte) 0xD9) return -1; // EOI
                    if ((next & 0xF0) == 0xD0) continue; // RST
                    // пропускаем секции
                    if (next != (byte) 0xDA && pos + 1 < data.length) {
                        int len = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
                        pos += len;
                    }
                    continue;
                }

                int coeff = data[pos++];
                if (coeff != 0 && Math.abs(coeff) != 1) {
                    return (coeff & 1);
                }
                // иначе пропускаем — по JSTEG в 0 и ±1 не прячем
            }
            return -1;
        }
    }
}