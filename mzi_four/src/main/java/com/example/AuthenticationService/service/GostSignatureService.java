package com.example.AuthenticationService.service;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

@Service
public class GostSignatureService {

    private KeyPair keyPair;

    public void generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
        kpg.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA"), new SecureRandom());
        keyPair = kpg.generateKeyPair();
    }

    public String sign(String message) throws Exception {
        if (keyPair == null) throw new IllegalStateException("Generate keys first");
        Signature sig = Signature.getInstance("1.2.643.7.1.1.3.2", "BC");
        sig.initSign(keyPair.getPrivate());
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] der = sig.sign();
        byte[] raw = derToRaw(der);
        return bytesToHex(raw);
    }

    public boolean verify(String message, String signatureHex, String publicKeyHex) throws Exception {
        PublicKey pubKey = publicKeyFromHex(publicKeyHex);
        Signature sig = Signature.getInstance("1.2.643.7.1.1.3.2", "BC");
        sig.initVerify(pubKey);
        sig.update(message.getBytes(StandardCharsets.UTF_8));

        byte[] rawSig = hexToBytes(signatureHex);
        if (rawSig.length > 64) {
            rawSig = derToRaw(rawSig);
        }
        return sig.verify(rawSig);
    }

    public String getPublicKeyHex() {
        if (keyPair == null) return null;
        ECPublicKey ecPub = (ECPublicKey) keyPair.getPublic();
        byte[] x = pad32(ecPub.getQ().getAffineXCoord().getEncoded());
        byte[] y = pad32(ecPub.getQ().getAffineYCoord().getEncoded());
        return bytesToHex(x) + bytesToHex(y);
    }

    private PublicKey publicKeyFromHex(String hex) throws Exception {
        byte[] x = hexToBytes(hex.substring(0, 64));
        byte[] y = hexToBytes(hex.substring(64));
        var spec = ECNamedCurveTable.getParameterSpec("Tc26-Gost-3410-12-256-paramSetA");
        var point = spec.getCurve().createPoint(new BigInteger(1, x), new BigInteger(1, y));
        var pubSpec = new ECPublicKeySpec(point, spec);
        return KeyFactory.getInstance("ECGOST3410-2012", "BC").generatePublic(pubSpec);
    }

    private byte[] derToRaw(byte[] der) {
        if (der[0] != 0x30) return der;
        int pos = 2;
        pos++;
        int rLen = der[pos++] & 0xff;
        byte[] r = new byte[32];
        int rOffset = Math.max(0, rLen - 32);
        System.arraycopy(der, pos + rOffset, r, 32 - (rLen - rOffset), rLen - rOffset);
        pos += rLen;

        pos++;
        int sLen = der[pos++] & 0xff;
        byte[] s = new byte[32];
        int sOffset = Math.max(0, sLen - 32);
        System.arraycopy(der, pos + sOffset, s, 32 - (sLen - sOffset), sLen - sOffset);

        byte[] raw = new byte[64];
        System.arraycopy(r, 0, raw, 0, 32);
        System.arraycopy(s, 0, raw, 32, 32);
        return raw;
    }

    private byte[] pad32(byte[] b) {
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