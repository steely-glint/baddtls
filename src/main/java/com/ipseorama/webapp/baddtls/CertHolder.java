/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ipseorama.webapp.baddtls;

import com.phono.srtplight.Log;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

/**
 *
 * @author tim
 */
public class CertHolder {

    /*
    create a cert like this :
     keytool -genkey -keyalg RSA -alias selfsigned -keystore keystore.jks -storepass password -validity 360 -keysize 2048

    */
    private Certificate _cert;
    private AsymmetricKeyParameter _key;

    CertHolder() throws UnrecoverableEntryException, KeyStoreException, IOException, FileNotFoundException, NoSuchAlgorithmException, CertificateException {
        if ((_key == null) || (_cert == null)) {
            loadKeyNCert();
            Log.debug("Key and cert loaded.");
        }
    }

    private void loadKeyNCert() throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

        // get user password and file input stream
        char[] password = "password".toCharArray();
        try (InputStream fis = this.getClass().getResourceAsStream("/keystore.jks")) {
            ks.load(fis, password);
            Key k = ks.getKey("selfsigned", password);
            _key = PrivateKeyFactory.createKey(k.getEncoded());
            java.security.cert.Certificate cert[] = ks.getCertificateChain("selfsigned");
            org.bouncycastle.asn1.x509.Certificate carry[] = new org.bouncycastle.asn1.x509.Certificate[cert.length];
            int n = 0;
            for (java.security.cert.Certificate c : cert) {
                carry[n++] = org.bouncycastle.asn1.x509.Certificate.getInstance(c.getEncoded());
            }
            _cert = new Certificate(carry);
        }
    }

    Certificate getCert() {
        return this._cert;
    }

    AsymmetricKeyParameter getKey() {
        return this._key;
    }

    public static void main(String argv[]) {
        try {
            Log.setLevel(Log.DEBUG);
            CertHolder s = new CertHolder();
            Log.debug("fingerprint is " + s.getPrint());
        } catch (Exception ex) {
            Log.error(ex.toString());
        }
    }

    String getPrint() throws IOException {
        org.bouncycastle.asn1.x509.Certificate fpc = _cert.getCertificateAt(0);
        return getPrint(fpc);
    }

    public static String getPrint(org.bouncycastle.asn1.x509.Certificate fpc) throws IOException {
        StringBuilder b = new StringBuilder();
        byte[] enc = fpc.getEncoded();
        SHA256Digest d = new SHA256Digest();
        d.update(enc, 0, enc.length);
        byte[] result = new byte[d.getDigestSize()];
        d.doFinal(result, 0);
        for (byte r : result) {
            String dig = Integer.toHexString((0xff) & r).toUpperCase();
            if (dig.length() == 1) {
                b.append('0');
            }
            b.append(dig).append(":");
        }
        b.deleteCharAt(b.length() - 1);
        return b.toString();
    }
}
