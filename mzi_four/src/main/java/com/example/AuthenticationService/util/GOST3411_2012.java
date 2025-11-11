package com.example.AuthenticationService.util;

import java.util.Arrays;

public class GOST3411_2012 {
    private static final byte[] IV512 = new byte[64];
    private static final byte[] IV256 = new byte[64];
    private static final long[] A = {
            0x8e20faa72ba0b470L,0x47107ddd9b505a38L,0xad08b0e0c3282d1cL,0xd8045870ef14980eL,
            0x6c022c38f90a4c07L,0x3601161cf205268dL,0x1b8e0b0e798c13c8L,0x83478b07b2468764L,
            0xa011d380818e8f40L,0x5086e740ce47c920L,0x2843fd2067adea10L,0x14aff010bdd87508L,
            0x0ad97808d06cb404L,0x05e23c0468365a02L,0x8c711e02341b2d01L,0x46b60f011a83988eL,
            0x90dab52a387ae76fL,0x486dd4151c3dfdb9L,0x24b86a840e90f0d2L,0x125c354207487869L,
            0x092e94218d243cbaL,0x8a174a9ec8121e5dL,0x4585254f64090fa0L,0xaccc9ca9328a8950L,
            0x9d4df05d5f661451L,0xc0a878a0a1330aa6L,0x60543c50de970553L,0x302a1e286fc58ca7L,
            0x18150f14b9ec46ddL,0x0c84890ad27623e0L,0x0642ca05693b9f70L,0x0321658cba93c138L,
            0x86275df09ce8aaa8L,0x439da0784e745554L,0xafc0503c273aa42aL,0xd960281e9d1d5215L,
            0xe230140fc0802984L,0x71180a8960409a42L,0xb60c05ca30204d21L,0x5b068c651810a89eL,
            0x456c34887a3805b9L,0xac361a443d1c8cd2L,0x561b0d22900e4669L,0x2b838811480723baL,
            0x9bcf4486248d9f5dL,0xc3e9224312c8c1a0L,0xeffa11af0964ee50L,0xf97d86d98a327728L,
            0xe4fa2054a80b329cL,0x727d102a548b194eL,0x39b008152acb8227L,0x9258048415eb419dL,
            0x492c024284fbaec0L,0xaa16012142f35760L,0x550b8e9e21f7a530L,0xa48b474f9ef5dc18L,
            0x70a6a56e2440598eL,0x3853dc371220a247L,0x1ca76e95091051a5L,0x0edd37c48a08a6d8L,
            0x07e095624504536cL,0x8d70c431ac02a736L,0xc83862965601dd1bL,0x641c314b2b8ee083L
    };
    private static final byte[] C = new byte[12*64];
    static {
        for (int i = 0; i < 12; i++) {
            Arrays.fill(C, i*64, (i+1)*64, (byte) (i+1));
        }
    }
    private static byte[] xor(byte[] a, byte[] b) {
        byte[] r = new byte[a.length];
        for (int i = 0; i < a.length; i++) r[i] = (byte)(a[i]^b[i]);
        return r;
    }
    private static byte[] S(byte[] v) {
        byte[] s = new byte[64];
        for (int i = 0; i < 64; i++) s[i] = (byte)((v[i]&0xF0)|((v[i]&0x0F)^0x0F));
        return s;
    }
    private static byte[] P(byte[] v) {
        byte[] r = new byte[64];
        for (int i = 0; i < 64; i++) r[i] = v[(i*11)%64];
        return r;
    }
    private static byte[] L(byte[] v) {
        long[] t = new long[8];
        for (int i=0;i<8;i++) {
            long w=0;
            for (int j=0;j<8;j++) w=(w<<8)|(v[i*8+j]&0xFFL);
            long x=0;
            for(int k=0;k<64;k++){
                if((w>>(63-k)&1)==1)x^=A[k];
            }
            t[i]=x;
        }
        byte[] r=new byte[64];
        for(int i=0;i<8;i++){
            for(int j=0;j<8;j++){
                r[i*8+j]=(byte)(t[i]>>(56-8*j));
            }
        }
        return r;
    }
    private static byte[] KeySchedule(byte[] K,int i){
        K=xor(K,Arrays.copyOfRange(C,i*64,(i+1)*64));
        K=S(K);K=P(K);K=L(K);
        return K;
    }
    private static byte[] E(byte[] K,byte[] m){
        byte[] state=xor(K,m);
        for(int i=0;i<12;i++){
            state=S(state);state=P(state);state=L(state);
            K=KeySchedule(K,i);
            state=xor(state,K);
        }
        return state;
    }
    private static byte[] g(byte[] N,byte[] m,byte[] h){
        byte[] K=xor(h,N);
        K=S(K);K=P(K);K=L(K);
        byte[] t=E(K,m);
        t=xor(h,t);
        byte[] G=xor(t,m);
        return G;
    }
    private static byte[] pad(byte[] m){
        if(m.length==64)return m;
        byte[] r=new byte[64];
        int len=m.length;
        System.arraycopy(m,0,r,64-len,len);
        r[63-len]=(byte)0x01;
        return r;
    }
    public static String hash512(byte[] M){
        byte[] h=IV512.clone();
        byte[] N=new byte[64];
        byte[] S=new byte[64];
        int len=M.length;
        while(len>64){
            byte[] m=Arrays.copyOfRange(M,len-64,len);
            h=g(N,m,h);
            long bits=512;for(int i=0;i<64;i++){int carry=(N[i]&0xFF)+(int)(bits&0xFF)+((i>0)?0:0);N[i]=(byte)(carry&0xFF);}
            for(int i=0;i<64;i++){int carry=(S[i]&0xFF)+(m[i]&0xFF);S[i]=(byte)(carry&0xFF);}
            len-=64;
        }
        byte[] m=pad(Arrays.copyOfRange(M,0,len));
        h=g(N,m,h);
        long bits=len*8;for(int i=0;i<64;i++){int carry=(N[i]&0xFF)+(int)(bits&0xFF)+((i>0)?0:0);N[i]=(byte)(carry&0xFF);}
        for(int i=0;i<64;i++){int carry=(S[i]&0xFF)+(m[i]&0xFF);S[i]=(byte)(carry&0xFF);}
        h=g(new byte[64],h,N);
        h=g(new byte[64],h,S);
        StringBuilder sb=new StringBuilder();
        for(byte b:h)sb.append(String.format("%02x",b));
        return sb.toString();
    }
    public static String hash256(byte[] M){
        String h=hash512(M);
        return h.substring(0,64);
    }
}
