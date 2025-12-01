package com.example.AuthenticationService.service;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.util.HexFormat;

@Service
public class EciesService {

    private KeyPair keyPair;
    private static final String CURVE_NAME = "secp256r1";

    public void generateKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(CURVE_NAME), new SecureRandom());
        keyPair = kpg.generateKeyPair();
    }

    public String encrypt(String message, String publicKeyHex) throws Exception {
        PublicKey recipientPub = publicKeyFromHex(publicKeyHex);
        ECNamedCurveParameterSpec curveSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);

        SecureRandom rnd = new SecureRandom();
        BigInteger k = BigInteger.probablePrime(curveSpec.getN().bitLength(), rnd);

        ECPoint R = curveSpec.getG().multiply(k);
        java.security.spec.ECPoint w = ((ECPublicKey) recipientPub).getW();
        ECPoint recipientPoint = curveSpec.getCurve().createPoint(w.getAffineX(), w.getAffineY());
        ECPoint sharedPoint = recipientPoint.multiply(k);

        byte[] sharedSecret = sharedPoint.normalize().getAffineXCoord().getEncoded();
        byte[] keyMaterial = kdf(sharedSecret, 32);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec aesKey = new SecretKeySpec(keyMaterial, 0, 16, "AES");
        byte[] iv = new byte[16];
        rnd.nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));

        byte[] ciphertext = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        byte[] Renc = R.getEncoded(false);
        byte[] result = new byte[Renc.length + iv.length + ciphertext.length];
        System.arraycopy(Renc, 0, result, 0, Renc.length);
        System.arraycopy(iv, 0, result, Renc.length, iv.length);
        System.arraycopy(ciphertext, 0, result, Renc.length + iv.length, ciphertext.length);

        return HexFormat.of().formatHex(result);
    }

    public String decrypt(String encryptedHex) throws Exception {
        byte[] data = HexFormat.of().parseHex(encryptedHex);
        ECNamedCurveParameterSpec curveSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);

        int pointSize = 65;
        byte[] Renc = new byte[pointSize];
        System.arraycopy(data, 0, Renc, 0, pointSize);
        ECPoint R = curveSpec.getCurve().decodePoint(Renc);

        byte[] iv = new byte[16];
        System.arraycopy(data, pointSize, iv, 0, 16);

        byte[] ciphertext = new byte[data.length - pointSize - 16];
        System.arraycopy(data, pointSize + 16, ciphertext, 0, ciphertext.length);

        BigInteger d = ((ECPrivateKey) keyPair.getPrivate()).getS();
        ECPoint sharedPoint = R.multiply(d);

        byte[] sharedSecret = sharedPoint.normalize().getAffineXCoord().getEncoded();
        byte[] keyMaterial = kdf(sharedSecret, 32);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec aesKey = new SecretKeySpec(keyMaterial, 0, 16, "AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));

        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }

    public String getPublicKeyHex() {
        java.security.spec.ECPoint w = ((ECPublicKey) keyPair.getPublic()).getW();
        byte[] x = padTo32(w.getAffineX().toByteArray());
        byte[] y = padTo32(w.getAffineY().toByteArray());
        return "04" + HexFormat.of().formatHex(x) + HexFormat.of().formatHex(y);
    }

    private PublicKey publicKeyFromHex(String hex) throws Exception {
        if (hex.startsWith("04")) hex = hex.substring(2);
        byte[] xBytes = HexFormat.of().parseHex(hex.substring(0, 64));
        byte[] yBytes = HexFormat.of().parseHex(hex.substring(64));
        java.security.spec.ECPoint point = new java.security.spec.ECPoint(
                new BigInteger(1, xBytes), new BigInteger(1, yBytes));

        // КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ: используем ECParameterSpec из JCE
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(CURVE_NAME));
        ECParameterSpec ecParamSpec = params.getParameterSpec(ECParameterSpec.class);

        ECPublicKeySpec keySpec = new ECPublicKeySpec(point, ecParamSpec);
        return KeyFactory.getInstance("EC").generatePublic(keySpec);
    }

    private byte[] kdf(byte[] z, int len) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] out = new byte[len];
        int pos = 0;
        int counter = 1;
        while (pos < len) {
            md.update(z);
            md.update(new byte[]{
                    (byte) (counter >> 24),
                    (byte) (counter >> 16),
                    (byte) (counter >> 8),
                    (byte) counter
            });
            counter++;
            byte[] hash = md.digest();
            System.arraycopy(hash, 0, out, pos, Math.min(hash.length, len - pos));
            pos += hash.length;
        }
        return out;
    }

    private byte[] padTo32(byte[] b) {
        if (b.length == 32) return b;
        if (b.length > 32) {
            byte[] res = new byte[32];
            System.arraycopy(b, b.length - 32, res, 0, 32);
            return res;
        }
        byte[] res = new byte[32];
        System.arraycopy(b, 0, res, 32 - b.length, b.length);
        return res;
    }
}