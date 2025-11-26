package com.example.AuthenticationService.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;

@Service
public class GostSignatureService {

    private KeyPair keyPair;

    public void generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
        kpg.initialize(new org.bouncycastle.jce.spec.ECGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA"));
        keyPair = kpg.generateKeyPair();
    }

    public String sign(String message) throws Exception {
        Signature sig = Signature.getInstance("1.2.643.7.1.1.3.2", "BC"); // <-- вот это работает!
        sig.initSign(keyPair.getPrivate());
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = sig.sign();
        return bytesToHex(signature);
    }

    public boolean verify(String message, String signatureHex, String publicKeyHex) throws Exception {
        PublicKey pubKey = publicKeyFromHex(publicKeyHex);
        Signature sig = Signature.getInstance("1.2.643.7.1.1.3.2", "BC");
        sig.initVerify(pubKey);
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        return sig.verify(hexToBytes(signatureHex));
    }

    public String getPublicKeyHex() {
        var ecPub = (org.bouncycastle.jce.interfaces.ECPublicKey) keyPair.getPublic();
        byte[] x = pad32(ecPub.getQ().getAffineXCoord().getEncoded());
        byte[] y = pad32(ecPub.getQ().getAffineYCoord().getEncoded());
        return bytesToHex(x) + bytesToHex(y);
    }

    private PublicKey publicKeyFromHex(String hex) throws Exception {
        byte[] x = hexToBytes(hex.substring(0, 64));
        byte[] y = hexToBytes(hex.substring(64));
        var spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("Tc26-Gost-3410-12-256-paramSetA");
        var point = spec.getCurve().createPoint(new BigInteger(1, x), new BigInteger(1, y));
        var pubSpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(point, spec);
        return KeyFactory.getInstance("ECGOST3410-2012", "BC").generatePublic(pubSpec);
    }

    private byte[] pad32(byte[] b) {
        if (b.length >= 32) {
            if (b.length > 32) {
                byte[] res = new byte[32];
                System.arraycopy(b, b.length - 32, res, 0, 32);
                return res;
            }
            return b;
        }
        byte[] res = new byte[32];
        System.arraycopy(b, 0, res, 32 - b.length, b.length);
        return res;
    }

    private String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte bb : b) sb.append(String.format("%02x", bb));
        return sb.toString();
    }

    private byte[] hexToBytes(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }
}