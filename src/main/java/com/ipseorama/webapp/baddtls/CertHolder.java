/*
 * Copyright (C) 2015 Westhawk Ltd<thp@westhawk.co.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package com.ipseorama.webapp.baddtls;

import com.phono.srtplight.Log;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 *
 * @author tim
 */
public class CertHolder {

    private static final Provider PROVIDER = new BouncyCastleProvider();

    private Certificate _cert;
    private AsymmetricKeyParameter _key;

    CertHolder() throws Exception {
        if ((_key == null) || (_cert == null)) {
            mkSelfSignedCert();
            Log.debug("Key and cert loaded.");
        }
    }

    private void mkSelfSignedCert() throws Exception {

        //Security.addProvider(PROVIDER);
        SecureRandom random = new SecureRandom();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024, random);
        KeyPair keypair = kpGen.generateKeyPair();
        PrivateKey key = keypair.getPrivate();
        Date notBefore = new Date(System.currentTimeMillis() - 10000);
        Date notAfter = new Date(System.currentTimeMillis() + 100000);
        // Prepare the information required for generating an X.509 certificate.
        X500Name owner = new X500Name("CN=" + "evil@baddtls.com");
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                owner, new BigInteger(64, random), notBefore, notAfter, owner, keypair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(key);
        X509CertificateHolder certHolder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(certHolder);
        cert.verify(keypair.getPublic());
        org.bouncycastle.asn1.x509.Certificate carry[] = new org.bouncycastle.asn1.x509.Certificate[1];
        carry[0] = org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded());
        _cert = new Certificate(carry);
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
