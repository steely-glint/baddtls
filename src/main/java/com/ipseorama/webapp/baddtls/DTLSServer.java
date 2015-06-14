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
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.SecureRandom;
import java.util.Hashtable;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.DTLSServerProtocol;
import org.bouncycastle.crypto.tls.DTLSTransport;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.tls.ExtensionType;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsSRTPUtils;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.tls.UseSRTPData;
import org.ice4j.TransportAddress;

/**
 *
 * @author tim
 */
class DTLSServer extends
        DefaultTlsServer implements org.bouncycastle.crypto.tls.DatagramTransport, Runnable {

    private final DatagramSocket _ds;
    private final TransportAddress _dest;

    private DTLSServerProtocol _serverProtocol;
    private boolean _isShutdown;
    private Thread _acceptor;
    private final CertHolder _cert;
    private final DtlsTransportAvailableListener _al;
    private final String _ffp;
    private boolean _verified = false;

    public DTLSServer(CertHolder cert, DatagramSocket lds, TransportAddress rta, DtlsTransportAvailableListener al, String farFingerprint) throws Exception {

        _al = al;
        _ds = lds;
        _dest = rta;
        _cert = cert;
        _ffp = farFingerprint;
        if ((_ds != null) && (_dest != null)) {
            SecureRandom secureRandom = new SecureRandom();
            _serverProtocol = new DTLSServerProtocol(secureRandom);
            _acceptor = new Thread(this);
            _acceptor.setName("DTLSServer");
            _acceptor.start();
        } else {
            Log.debug("no socket or destination");
        }

    }

    static String getHex(byte[] in) {
        return getHex(in, in.length);
    }

    static String getHex(byte[] in, int len) {
        char cmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        StringBuffer ret = new StringBuffer();
        int top = Math.min(in.length, len);
        for (int i = 0; i < top; i++) {
            ret.append("(byte)0x");
            ret.append(cmap[0x0f & (in[i] >>> 4)]);
            ret.append(cmap[in[i] & 0x0f]);
            ret.append(", ");
            if ((i > 0) && ((i % 8) == 0)) {
                ret.append("\n");
            }
        }
        return ret.toString();
    }

    public void run() {
        try {
            DTLSTransport dtlsServer = _serverProtocol.accept(this, this);
            Log.debug("DTLS accept. verified = " + _verified);
            if (_verified) {
                _al.transportAvailable(dtlsServer);
            } else {
                Log.error("Not the fingerprint we were looking for (waves hand)");
            }
            // dtlsServer.close(); somehow we should do this....
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public CertificateRequest getCertificateRequest() {
        return new CertificateRequest(new short[]{ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign}, null, null);
    }

    @Override
    protected ProtocolVersion getMaximumVersion() {
        return ProtocolVersion.DTLSv10;
    }

    @Override
    protected ProtocolVersion getMinimumVersion() {
        return ProtocolVersion.DTLSv10;
    }

    @Override
    protected TlsSignerCredentials getRSASignerCredentials()
            throws IOException {
        return new DefaultTlsSignerCredentials(context, _cert.getCert(), _cert.getKey());
    }

    @Override
    public Hashtable getServerExtensions()
            throws IOException {
        Hashtable serverExtensions = super.getServerExtensions();
        // in theory we may want to offer srtp extensions - but not in the pure data case.
        return serverExtensions;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void notifyClientCertificate(Certificate clientCertificate)
            throws IOException {
        org.bouncycastle.asn1.x509.Certificate[] cs = clientCertificate.getCertificateList();
        if ((cs == null) || (cs.length < 1)) {
            throw new IOException("no certs offered");
        }
        String ffp = CertHolder.getPrint(cs[0]);
        if (!ffp.equalsIgnoreCase(_ffp)) {
            throw new IOException("fingerprints don't match ");
        }
        _verified = true;
    }

    /**
     * {@inheritDoc}
     *
     * Makes sure that the DTLS extended client hello contains the
     * <tt>use_srtp</tt> extension.
     */
    @Override
    @SuppressWarnings("rawtypes")
    public void processClientExtensions(Hashtable clientExtensions)
            throws IOException {
        UseSRTPData d
                = TlsSRTPUtils.getUseSRTPExtension(clientExtensions);

        if (d == null) {
            Log.debug("Browser didn't send a use_srtp in the client hello");
        }
        // remove something chrome sends wrongly
        if (clientVersion == ProtocolVersion.DTLSv10) {
            Log.debug("checking for signaturealgo extension as DTLS 1.0 shouldn't support it");
            Integer salg = new Integer(ExtensionType.signature_algorithms);
            if (clientExtensions.containsKey(salg)) {
                Log.debug("removing signature algos for now as DTLS 1.0 shouldn't support it");
                clientExtensions.remove(salg);
            }
        }
        super.processClientExtensions(clientExtensions);
    }

    @Override
    public int getReceiveLimit() throws IOException {
        return 1500;
    }

    @Override
    public int getSendLimit() throws IOException {
        return 1500;
    }

    public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
        Log.debug("recv ");
        DatagramPacket p = new DatagramPacket(buf, off, len);
        _ds.setSoTimeout(waitMillis);
        _ds.receive(p);
        Log.debug("recv'd " + p.getLength());

        return p.getLength();
    }

    @Override
    public void send(byte[] buf, int off, int len) throws IOException {
        DatagramPacket p = new DatagramPacket(buf, off, len, _dest);
        _ds.send(p);
        Log.debug("sent " + p.getLength() + " to " + _dest.toString());

    }

    @Override
    public void close() throws IOException {
        _isShutdown = true;
        _ds.close();

    }

}
