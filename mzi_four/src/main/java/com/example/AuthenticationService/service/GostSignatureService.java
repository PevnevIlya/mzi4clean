package com.example.AuthenticationService.service;

import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

@Service
public class GostSignatureService {

    private static final String CURVE_NAME = "GostR3410-2012-256";
    private static final String SIGNATURE_ALG = "GOST3411-2012-256withGOST3410-2012-256";

    private KeyPair currentKeyPair;

    public void generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012");
        kpg.initialize(new ECGenParameterSpec(CURVE_NAME));
        currentKeyPair = kpg.generateKeyPair();
    }

    public String sign(String message) throws Exception {
        if (currentKeyPair == null) throw new IllegalStateException("Keys not generated");
        Signature sig = Signature.getInstance(SIGNATURE_ALG);
        sig.initSign(currentKeyPair.getPrivate());
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = sig.sign();
        return bytesToHex(signature);
    }

    public boolean verify(String message, String signatureHex, String publicKeyHex) throws Exception {
        PublicKey publicKey = publicKeyFromHex(publicKeyHex);
        Signature sig = Signature.getInstance(SIGNATURE_ALG);
        sig.initVerify(publicKey);
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        return sig.verify(hexToBytes(signatureHex));
    }

    public String getPublicKeyHex() {
        if (currentKeyPair == null) return null;
        ECPoint w = ((java.security.interfaces.ECPublicKey) currentKeyPair.getPublic()).getW();
        byte[] x = pad32(w.getAffineX().toByteArray());
        byte[] y = pad32(w.getAffineY().toByteArray());
        return bytesToHex(x) + bytesToHex(y);
    }

    public PublicKey publicKeyFromHex(String hex) throws Exception {
        byte[] x = hexToBytes(hex.substring(0, 64));
        byte[] y = hexToBytes(hex.substring(64));
        ECParameterSpec params = ((java.security.interfaces.ECPublicKey) currentKeyPair.getPublic()).getParams();
        ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
        KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012");
        return kf.generatePublic(spec);
    }

    private byte[] pad32(byte[] data) {
        if (data.length == 32) return data;
        byte[] padded = new byte[32];
        int offset = data.length > 32 ? data.length - 32 : 0;
        System.arraycopy(data, offset, padded, 32 - (data.length - offset), data.length - offset);
        return padded;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}