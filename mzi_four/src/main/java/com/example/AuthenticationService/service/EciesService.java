package com.example.AuthenticationService.service;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.HexFormat;

@Service
public class EciesService {

    private KeyPair keyPair;
    private static final String CURVE = "secp256r1";

    public void generateKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(CURVE), new SecureRandom());
        keyPair = kpg.generateKeyPair();
    }

    public String encrypt(String message, String publicKeyHex) throws Exception {
        PublicKey pubKey = publicKeyFromHex(publicKeyHex);
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE);

        SecureRandom random = new SecureRandom();
        BigInteger k = BigInteger.probablePrime(spec.getN().bitLength(), random);

        ECPoint R = spec.getG().multiply(k);
        ECPoint P = ((org.bouncycastle.jce.interfaces.ECPublicKey) pubKey).getQ();
        ECPoint S = P.multiply(k);

        byte[] sharedX = S.getAffineXCoord().getEncoded();
        byte[] keyMaterial = kdf(sharedX, 32);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec aesKey = new SecretKeySpec(keyMaterial, 0, 16, "AES");
        byte[] iv = new byte[16];
        random.nextBytes(iv);
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
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE);

        int pointSize = 65;
        byte[] Renc = new byte[pointSize];
        System.arraycopy(data, 0, Renc, 0, pointSize);
        ECPoint R = spec.getCurve().decodePoint(Renc);

        byte[] iv = new byte[16];
        System.arraycopy(data, pointSize, iv, 0, 16);

        byte[] ciphertext = new byte[data.length - pointSize - 16];
        System.arraycopy(data, pointSize + 16, ciphertext, 0, ciphertext.length);

        PrivateKey priv = keyPair.getPrivate();
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(priv);
        ka.doPhase(KeyFactory.getInstance("EC").generatePublic(
                new org.bouncycastle.jce.spec.ECPublicKeySpec(R, spec)), true);
        byte[] shared = ka.generateSecret();

        byte[] keyMaterial = kdf(shared, 32);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec aesKey = new SecretKeySpec(keyMaterial, 0, 16, "AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));

        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }

    public String getPublicKeyHex() {
        ECPoint Q = ((org.bouncycastle.jce.interfaces.ECPublicKey) keyPair.getPublic()).getQ();
        return HexFormat.of().formatHex(Q.getEncoded(false));
    }

    private PublicKey publicKeyFromHex(String hex) throws Exception {
        byte[] bytes = HexFormat.of().parseHex(hex);
        ECPoint point = ECNamedCurveTable.getParameterSpec(CURVE).getCurve().decodePoint(bytes);
        var pubSpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(point,
                ECNamedCurveTable.getParameterSpec(CURVE));
        return KeyFactory.getInstance("EC").generatePublic(pubSpec);
    }

    private byte[] kdf(byte[] z, int length) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] result = new byte[length];
        int pos = 0;
        int counter = 1;
        while (pos < length) {
            digest.update(z);
            digest.update(new byte[]{(byte) (counter >> 24), (byte) (counter >> 16), (byte) (counter >> 8), (byte) counter});
            counter++;
            byte[] hash = digest.digest();
            System.arraycopy(hash, 0, result, pos, Math.min(hash.length, length - pos));
            pos += hash.length;
        }
        return result;
    }
}