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

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.Agent;
import org.ice4j.ice.IceMediaStream;
import org.ice4j.ice.NominationStrategy;
import org.ice4j.ice.harvest.StunCandidateHarvester;
import com.phono.srtplight.Log;
import java.io.IOException;
import java.net.DatagramSocket;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.crypto.tls.DTLSTransport;
import org.ice4j.ice.Candidate;
import org.ice4j.ice.CandidatePair;
import org.ice4j.ice.CandidateType;
import org.ice4j.ice.Component;
import org.ice4j.ice.IceProcessingState;
import org.ice4j.ice.RemoteCandidate;

/**
 *
 * @author tim
 */
public class IceConnect implements PropertyChangeListener {

    private long startTime;
    private Agent _localAgent;
    private DTLSServer _dtls;
    private static CertHolder _cert;
    private String _ffp;
    public Runnable cleanup;

    IceConnect(int port) throws Exception {
        _cert = new CertHolder();
        _ffp = null;
        _localAgent = createAgent(false);
        _localAgent.addStateChangeListener(this);

        _localAgent.setNominationStrategy(
                NominationStrategy.NOMINATE_HIGHEST_PRIO);

        //let them fight ... fights forge character.
        _localAgent.setControlling(false);

        //STREAMS
        createStream(port, "data", _localAgent);

    }

    void startIce() {
        _localAgent.startConnectivityEstablishment();

    }

    void buildIce(String ufrag, String upass) throws InterruptedException, IllegalArgumentException, IOException {
        //transferRemoteCandidates(localAgent, remotePeer);
        for (IceMediaStream stream : _localAgent.getStreams()) {
            stream.setRemoteUfrag(ufrag);
            stream.setRemotePassword(upass);
        }
        Log.info("LocalAgent:\n" + _localAgent);
    }

    String getUfrag() {
        return _localAgent.getLocalUfrag();
    }

    String getPass() {
        return _localAgent.getLocalPassword();
    }

    String getPrint() {
        String ret = "";
        try {
            ret = _cert.getPrint();
        } catch (IOException ex) {
            Log.debug("cant get fingerprint" + ex.toString());
        }
        return ret;
    }

    void setFarFingerprint(String ffp) {
        _ffp = ffp;
    }

    List<Candidate> getCandidates() {
        ArrayList<Candidate> ret = new ArrayList();
        IceMediaStream st = getStream("data");
        for (Component comp : st.getComponents()) {
            for (Candidate candy : comp.getLocalCandidates()) {
                if (candy.getHostAddress().isIPv6()) {
                    Log.debug("not adding " + candy);
                } else {
                    Log.debug("adding " + candy);
                    ret.add(candy);
                }
            }
        }
        return ret;
    }

    @Override
    public void propertyChange(PropertyChangeEvent evt) {
        Log.debug("got PCE evt on " + evt.getPropertyName() + " value is now " + evt.getNewValue());
        if (evt.getPropertyName().equals("IceProcessingState")) {
            IceProcessingState st = (IceProcessingState) evt.getNewValue();

            switch (st) {
                case COMPLETED:
                    IceMediaStream s = getStream("data");

                    Component comp = s.getComponent(1);
                    Transport t = comp.getTransport();

                    CandidatePair cp = comp.getSelectedPair();
                    DatagramSocket lds = cp.getLocalCandidate().getDatagramSocket();
                    Log.debug("selected Datagram socket" + lds.toString());
                    TransportAddress rta = cp.getRemoteCandidate().getTransportAddress();
                    if (lds.isBound()) {
                        Log.debug("local ds bound to " + lds.getLocalSocketAddress());
                    }
                    if (lds.isConnected()) {
                        Log.debug("local ds connected to" + lds.getRemoteSocketAddress());
                    }
                    try {
                        DtlsTransportAvailableListener al = new DtlsTransportAvailableListener() {

                            @Override
                            public void transportAvailable(DTLSTransport trans) {
                                Log.debug("Transport available");
                            }

                        };
                        _dtls = new DTLSServer(_cert, lds, rta, al, _ffp);
                    } catch (Exception ex) {
                        Log.debug("DTLS exception");
                        Log.error(ex.toString());
                    }
                    break;

                case RUNNING:
                    Log.debug("Ice Running");
                    break;
                case FAILED:
                    Log.debug("Ice Failed");
                    cleanup.run();
                    break;
                case TERMINATED:
                    Log.debug("Ice Terminated");
                    _localAgent.free();
                    cleanup.run();
                    break;
                case WAITING:
                    Log.debug("Ice Waiting");
                    break;
            }
        }
    }

    protected Agent createAgent(boolean isTrickling) throws IllegalArgumentException, IOException {
        Agent agent = new Agent();
        agent.setTrickling(isTrickling);

        // STUN
        StunCandidateHarvester stunHarv = new StunCandidateHarvester(
                new TransportAddress("stun.l.google.com", 19302, Transport.UDP));

        agent.addCandidateHarvester(stunHarv);
        // TURN - todo - 
        return agent;
    }

    private IceMediaStream createStream(int rtpPort,
            String streamName,
            Agent agent) throws IllegalArgumentException, IOException {
        IceMediaStream stream = agent.createMediaStream(streamName);
        //TODO: component creation should probably be part of the library. it
        //should also be started after we've defined all components to be
        //created so that we could run the harvesting for everyone of them
        //simultaneously with the others.
        //rtp
        agent.createComponent(
                stream, Transport.UDP, rtpPort, rtpPort, rtpPort + 100);
        return stream;
    }

    void addCandidate(String foundation, String component, String protocol, String priority, String ip, String port, String type) {
        IceMediaStream localStream = getStream("data");
        List<Component> localComponents = localStream.getComponents();
        int cid = Integer.parseInt(component);
        for (Component localComponent : localComponents) {
            int id = localComponent.getComponentID();
            if (cid == id) {
                int iport = Integer.parseInt(port);
                long lpriority = Long.parseLong(priority);
                TransportAddress ta = new TransportAddress(ip, iport, Transport.parse(protocol));
                // localComponent.setDefaultRemoteCandidate(remoteComponent.getDefaultCandidate());
                localComponent.addRemoteCandidate(new RemoteCandidate(
                        ta,
                        localComponent,
                        CandidateType.parse(type),
                        foundation,
                        lpriority,
                        null));
            }

        }

    }

    IceMediaStream getStream(String target) {
        IceMediaStream ret = null;
        List<IceMediaStream> l = _localAgent.getStreams();
        Log.debug(" count of streams =" + l.size());
        for (IceMediaStream stream : l) {
            if (target.equals(stream.getName())) {
                Log.debug("found " + target);
                ret = stream;
                break;
            } else {
                Log.debug("looking at " + stream.getName());
            }
        }
        return ret;
    }

}
