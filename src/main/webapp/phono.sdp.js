
/* derived from Phono with original license quoted here */
/*!
 * Copyright 2013 Voxeo Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
;
(function() {

    // Helper library to translate to and from SDP and an intermediate javascript object
    // representation of candidates, offers and answers

    _parseLine = function(line) {
        var s1 = line.split("=");
        return {
            type: s1[0],
            contents: s1[1]
        }
    }

    _parseA = function(attribute) {
        var s1 = attribute.split(":");
        return {
            key: s1[0],
            params: attribute.substring(attribute.indexOf(":") + 1).split(" ")
        }
    }

    _parseM = function(media) {
        var s1 = media.split(" ");
        return {
            type: s1[0],
            port: s1[1],
            proto: s1[2],
            pts: media.substring((s1[0] + s1[1] + s1[2]).length + 3).split(" ")
        }
    }

    _parseO = function(media) {
        var s1 = media.split(" ");
        return {
            username: s1[0],
            id: s1[1],
            ver: s1[2],
            nettype: s1[3],
            addrtype: s1[4],
            address: s1[5]
        }
    }

    _parseC = function(media) {
        var s1 = media.split(" ");
        return {
            nettype: s1[0],
            addrtype: s1[1],
            address: s1[2]
        }
    }

    //a=candidate:257138899 1 udp 2113937151 192.168.0.151 53973 typ host generation 0
    //a=candidate:1 1 udp 1.0 192.168.157.40 40877 typ host name rtp network_name en0 username root password mysecret generation 0
    /*
     candidate-attribute   = "candidate" ":" foundation SP component-id SP
     transport SP
     priority SP
     connection-address SP     ;from RFC 4566
     port         ;port from RFC 4566
     SP cand-type
     [SP rel-addr]
     [SP rel-port]
     *(SP extension-att-name SP
     extension-att-value)
     
     foundation            = 1*32ice-char
     component-id          = 1*5DIGIT
     transport             = "UDP" / transport-extension
     transport-extension   = token              ; from RFC 3261
     priority              = 1*10DIGIT
     cand-type             = "typ" SP candidate-types
     candidate-types       = "host" / "srflx" / "prflx" / "relay" / token
     rel-addr              = "raddr" SP connection-address
     rel-port              = "rport" SP port
     extension-att-name    = byte-string    ;from RFC 4566
     extension-att-value   = byte-string
     ice-char              = ALPHA / DIGIT / "+" / "/"
     */
    _parseCandidate = function(params) {
        var candidate = {
            foundation: params[0],
            component: params[1],
            protocol: params[2],
            priority: params[3],
            ip: params[4],
            port: params[5]
        };
        var index = 6;
        while (index + 1 <= params.length) {
            if (params[index] == "typ")
                candidate["type"] = params[index + 1];
            if (params[index] == "generation")
                candidate["generation"] = params[index + 1];
            if (params[index] == "username")
                candidate["username"] = params[index + 1];
            if (params[index] == "password")
                candidate["password"] = params[index + 1];

            index += 2;
        }

        return candidate;
    }

    //a=rtcp:1 IN IP4 0.0.0.0
    _parseRtcp = function(params) {
        var rtcp = {
            port: params[0]
        };
        if (params.length > 1) {
            rtcp['nettype'] = params[1];
            rtcp['addrtype'] = params[2];
            rtcp['address'] = params[3];
        }
        return rtcp;
    }

    //a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:zvrxmXFpomTqz7CJYhN5G7JM3dVVxG/fZ0Il6DDo
    _parseCrypto = function(params) {
        var crypto = {
            'tag': params[0],
            'crypto-suite': params[1],
            'key-params': params[2]
        }
        return crypto;
    }
    _parseFingerprint = function(params) {
        var finger = {
            'hash': params[0],
            'print': params[1],
            'required': '1'
        }
        return finger;
    }

    //a=rtpmap:101 telephone-event/8000"
    _parseRtpmap = function(params) {
        var bits = params[1].split("/");
        var codec = {
            id: params[0],
            name: bits[0],
            clockrate: bits[1]
        }
        if (bits.length > 2) {
            codec.channels = bits[2];
        }
        return codec;
    }

    _parseSsrc = function(params, ssrc) {
        var ssrcObj = {};
        if (ssrc != undefined)
            ssrcObj = ssrc;
        ssrcObj.ssrc = params[0];
        var value = params[1];
        ssrcObj[value.split(":")[0]] = value.split(":")[1];
        return ssrcObj;
    }

    _parseGroup = function(params) {
        var group = {
            type: params[0]
        }
        group.contents = [];
        var index = 1;
        while (index + 1 <= params.length) {
            group.contents.push(params[index]);
            index = index + 1;
        }
        return group;
    }

    _parseMid = function(params) {
        var mid = params[0];
        return mid;
    }
    
    _parseSetup = function(params) {
        var setup = params[0];
        return setup;
    }

    // Object -> SDP

    _buildCandidate = function(candidateObj, iceObj) {
        var c = candidateObj;
        var sdp = "a=candidate:" + c.foundation + " " +
                c.component + " " +
                c.protocol.toUpperCase() + " " +
                c.priority + " " +
                c.ip + " " +
                c.port;
        if (c.type)
            sdp = sdp + " typ " + c.type;
        if (c.component == 1)
            sdp = sdp + " name rtp";
        if (c.component == 2)
            sdp = sdp + " name rtcp";
        sdp = sdp + " network_name en0";
        if (c.username && c.password) {
            sdp = sdp + " username " + c.username;
            sdp = sdp + " password " + c.password;
            if (!iceObj.ufrag)
                iceObj.ufrag = c.username;
            if (!iceObj.pwd)
                iceObj.pwd = c.username;
            ;
        } else if (iceObj) {
            if (iceObj.ufrag)
                sdp = sdp + " username " + iceObj.ufrag;
            if (iceObj.pwd)
                sdp = sdp + " password " + iceObj.pwd;
        } else {
            sdp = sdp + " username root password mysecret";// I know a secret
        }
        if (c.generation)
            sdp = sdp + " generation " + c.generation;
        sdp = sdp + "\r\n";
        return sdp;
    }

    _buildCodec = function(codecObj) {
        var sdp = "a=rtpmap:" + codecObj.id + " " + codecObj.name + "/" + codecObj.clockrate
        if (codecObj.channels) {
            sdp += "/" + codecObj.channels;
        }
        sdp += "\r\n";
        if (codecObj.ptime) {
            sdp += "a=ptime:" + codecObj.ptime;
            sdp += "\r\n";
        }
        return sdp;
    }

    _buildCrypto = function(cryptoObj) {
        var sdp = "a=crypto:" + cryptoObj.tag + " " + cryptoObj['crypto-suite'] + " " +
                cryptoObj["key-params"] + "\r\n";
        return sdp;
    }

    _buildFingerprint = function(fingerObj) {
        var sdp = "a=fingerprint:" + fingerObj.hash + " " + fingerObj.print + "\r\n";
        return sdp;
    }

    _buildMedia = function(sdpObj) {
        var sdp = "";
// move fingerprint and ice to outside the m=
        if (sdpObj.fingerprint) {
            sdp = sdp + _buildFingerprint(sdpObj.fingerprint);
        }
        if (sdpObj.ice) {
            var ice = sdpObj.ice;
            if (!ice.filterLines) {
                sdp = sdp + "a=ice-ufrag:" + ice.ufrag + "\r\n";
                sdp = sdp + "a=ice-pwd:" + ice.pwd + "\r\n";
            }
            if (ice.options) {
                sdp = sdp + "a=ice-options:" + ice.options + "\r\n";
            }
        }
        sdp += "m=" + sdpObj.media.type + " " + sdpObj.media.port + " " + sdpObj.media.proto;
        var mi = 0;
        while (mi + 1 <= sdpObj.media.pts.length) {
            sdp = sdp + " " + sdpObj.media.pts[mi];
            mi = mi + 1;
        }
        sdp = sdp + "\r\n";

        if (sdpObj.connection) {
            sdp = sdp + "c=" + sdpObj.connection.nettype + " " + sdpObj.connection.addrtype + " " +
                    sdpObj.connection.address + "\r\n";
        }

        if (sdpObj.mid) {
            sdp = sdp + "a=mid:" + sdpObj.mid + "\r\n";
        }

        if (sdpObj.setup) {
            sdp = sdp + "a=setup:" + sdpObj.setup + "\r\n";
        }

        if (sdpObj.rtcp) {
            sdp = sdp + "a=rtcp:" + sdpObj.rtcp.port + " " + sdpObj.rtcp.nettype + " " +
                    sdpObj.rtcp.addrtype + " " +
                    sdpObj.rtcp.address + "\r\n";
        }

        var ci = 0;
        while (ci + 1 <= sdpObj.candidates.length) {
            sdp = sdp + _buildCandidate(sdpObj.candidates[ci], sdpObj.ice);
            ci = ci + 1;
        }


        if (sdpObj.direction) {
            if (sdpObj.direction == "recvonly") {
                sdp = sdp + "a=recvonly\r\n";
            } else if (sdpObj.direction == "sendonly") {
                sdp = sdp + "a=sendonly\r\n";
            } else if (sdpObj.direction == "none") {
                sdp = sdp;
            } else {
                sdp = sdp + "a=sendrecv\r\n";
            }
        } else {
            sdp = sdp + "a=sendrecv\r\n";
        }



        if (sdpObj['rtcp-mux']) {
            sdp = sdp + "a=rtcp-mux" + "\r\n";
        }

        if (sdpObj.crypto) {
            sdp = sdp + _buildCrypto(sdpObj.crypto);
        }

        var cdi = 0;
        while (cdi + 1 <= sdpObj.codecs.length) {
            sdp = sdp + _buildCodec(sdpObj.codecs[cdi]);
            cdi = cdi + 1;
        }

        if (sdpObj.ssrc) {
            var ssrc = sdpObj.ssrc;
            if (ssrc.cname)
                sdp = sdp + "a=ssrc:" + ssrc.ssrc + " " + "cname:" + ssrc.cname + "\r\n";
            if (ssrc.mslabel)
                sdp = sdp + "a=ssrc:" + ssrc.ssrc + " " + "mslabel:" + ssrc.mslabel + "\r\n";
            if (ssrc.label)
                sdp = sdp + "a=ssrc:" + ssrc.ssrc + " " + "label:" + ssrc.label + "\r\n";
        }

        return sdp;
    }

// Entry points

    // Fake Phono for node.js or loose use
    if (typeof Phono == 'undefined') {
        Phono = {
            log: {debug: function(mess) {
                    console.log(mess);
                }}
        };
    }

    Phono.sdp = {
        // sdp: an SDP text string representing an offer or answer, missing candidates
        // Return an object representing the SDP in Jingle like constructs
        parseSDP: function(sdpString) {
            var contentsObj = {};
            contentsObj.contents = [];
            var sessionSDP = {ice: {}};
            var sdpObj = sessionSDP;

            // Iterate the lines
            var sdpLines = sdpString.split("\r\n");
            for (var sdpLine in sdpLines) {
                Phono.log.debug(sdpLines[sdpLine]);
                var line = _parseLine(sdpLines[sdpLine]);

                if (line.type == "o") {
                    contentsObj.session = _parseO(line.contents);
                }
                if (line.type == "m") {
                    // New m-line, 
                    // create a new content
                    var media = _parseM(line.contents);
                    sdpObj = {};
                    sdpObj.candidates = [];
                    sdpObj.codecs = [];
                    sdpObj.ice = sessionSDP.ice;
                    if (sessionSDP.fingerprint != null) {
                        sdpObj.fingerprint = sessionSDP.fingerprint;
                    }
                    sdpObj.media = media;
                    contentsObj.contents.push(sdpObj);
                }
                if (line.type == "c") {
                    if (sdpObj != null) {
                        sdpObj.connection = _parseC(line.contents);
                    } else {
                        contentsObj.connection = _parseC(line.contents);
                    }
                }
                if (line.type == "a") {
                    var a = _parseA(line.contents);
                    switch (a.key) {
                        case "candidate":
                            var candidate = _parseCandidate(a.params);
                            sdpObj.candidates.push(candidate);
                            break;
                        case "group":
                            var group = _parseGroup(a.params);
                            contentsObj.group = group;
                            break;
                        case "setup":
                            var setup = _parseSetup(a.params);
                            sdpObj.setup = setup;
                            break;
                        case "mid":
                            var mid = _parseMid(a.params);
                            sdpObj.mid = mid;
                            break;
                        case "rtcp":
                            var rtcp = _parseRtcp(a.params);
                            sdpObj.rtcp = rtcp;
                            break;
                        case "rtcp-mux":
                            sdpObj['rtcp-mux'] = true;
                            break;
                        case "rtpmap":
                            var codec = _parseRtpmap(a.params);
                            if (codec)
                                sdpObj.codecs.push(codec);
                            break;
                        case "sendrecv":
                            sdpObj.direction = "sendrecv";
                            break;
                        case "sendonly":
                            sdpObj.direction = "sendonly";
                            break;
                        case "recvonly":
                            sdpObj.recvonly = "recvonly";
                            break;
                        case "ssrc":
                            sdpObj.ssrc = _parseSsrc(a.params, sdpObj.ssrc);
                            break;
                        case "fingerprint":
                            var print = _parseFingerprint(a.params);
                            sdpObj.fingerprint = print;
                            break;
                        case "crypto":
                            var crypto = _parseCrypto(a.params);
                            sdpObj.crypto = crypto;
                            break;
                        case "ice-ufrag":
                            sdpObj.ice.ufrag = a.params[0];
                            break;
                        case "ice-pwd":
                            sdpObj.ice.pwd = a.params[0];
                            break;
                        case "ice-options":
                            sdpObj.ice.options = a.params[0];
                            break;
                    }
                }

            }
            return contentsObj;
        },
        // sdp: an object representing the body
        // Return a text string in SDP format  
        buildSDP: function(contentsObj) {
            // Write some constant stuff
            var session = contentsObj.session;
            var sdp =
                    "v=0\r\n";
            if (contentsObj.session) {
                var session = contentsObj.session;
                sdp = sdp + "o=" + session.username + " " + session.id + " " + session.ver + " " +
                        session.nettype + " " + session.addrtype + " " + session.address + "\r\n";
            } else {
                var id = new Date().getTime();
                var ver = 2;
                sdp = sdp + "o=-" + " 3" + id + " " + ver + " IN IP4 192.67.4.14" + "\r\n"; // does the IP here matter ?!?
            }

            sdp = sdp + "s=-\r\n" +
                    "t=0 0\r\n";

            if (contentsObj.connection) {
                var connection = contentsObj.connection;
                sdp = sdp + "c=" + connection.nettype + " " + connection.addrtype +
                        " " + connection.address + "\r\n";
            }
            if (contentsObj.group) {
                var group = contentsObj.group;
                sdp = sdp + "a=group:" + group.type;
                var ig = 0;
                while (ig + 1 <= group.contents.length) {
                    sdp = sdp + " " + group.contents[ig];
                    ig = ig + 1;
                }
                sdp = sdp + "\r\n";
            }

            var contents = contentsObj.contents;
            var ic = 0;
            while (ic + 1 <= contents.length) {
                var sdpObj = contents[ic];
                sdp = sdp + _buildMedia(sdpObj);
                ic = ic + 1;
            }
            return sdp;
        },
        // candidate: an SDP text string representing a cadidate
        // Return: an object representing the candidate in Jingle like constructs
        parseCandidate: function(candidateSDP) {
            var line = _parseLine(candidateSDP);
            if (line.contents)
                return _parseCandidate(line.contents.substring(line.contents.indexOf(":") + 1).split(" "));
        },
        // candidate: an object representing the body
        // Return a text string in SDP format
        buildCandidate: function(candidateObj) {
            return _buildCandidate(candidateObj);
        }
    };

    if (typeof window === 'undefined') {
        // Unit tests under node.js

        var SDP = {
            chromeVideo: "v=0\r\no=- 2242705449 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE audio video\r\na=msid-semantic: WMS mXFROJeVMQxDhCFH34Yukxots985y812wGPJ\r\nm=audio 49548 RTP/SAVPF 111 103 104 0 8 107 106 105 13 126\r\nc=IN IP4 192.67.4.11\r\na=rtcp:49548 IN IP4 192.67.4.11\r\na=candidate:521808905 1 udp 2113937151 192.67.4.11 49548 typ host generation 0\r\na=candidate:521808905 2 udp 2113937151 192.67.4.11 49548 typ host generation 0\r\na=ice-ufrag:rl/PIMG6Pd1h6Ymp\r\na=ice-pwd:jsymMG3rh3Fq1vK83jHyQVtt\r\na=ice-options:google-ice\r\na=fingerprint:sha-256 C0:F7:9C:63:AC:84:62:E9:0D:F5:3B:D9:F8:7E:53:29:E2:1F:44:41:84:D1:B6:D7:48:39:A5:64:1F:E7:B4:E4\r\na=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\na=sendrecv\r\na=mid:audio\r\na=rtcp-mux\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:f4OO7dHJbCQsjecAC+0TFp6g6KBXyOub6yBmx+Xx\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10\r\na=rtpmap:103 ISAC/16000\r\na=rtpmap:104 ISAC/32000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:107 CN/48000\r\na=rtpmap:106 CN/32000\r\na=rtpmap:105 CN/16000\r\na=rtpmap:13 CN/8000\r\na=rtpmap:126 telephone-event/8000\r\na=maxptime:60\r\na=ssrc:3666452233 cname:XsXQR1VfOels9+3s\r\na=ssrc:3666452233 msid:mXFROJeVMQxDhCFH34Yukxots985y812wGPJ mXFROJeVMQxDhCFH34Yukxots985y812wGPJa0\r\na=ssrc:3666452233 mslabel:mXFROJeVMQxDhCFH34Yukxots985y812wGPJ\r\na=ssrc:3666452233 label:mXFROJeVMQxDhCFH34Yukxots985y812wGPJa0\r\nm=video 49548 RTP/SAVPF 100 116 117\r\nc=IN IP4 192.67.4.11\r\na=rtcp:49548 IN IP4 192.67.4.11\r\na=candidate:521808905 1 udp 2113937151 192.67.4.11 49548 typ host generation 0\r\na=candidate:521808905 2 udp 2113937151 192.67.4.11 49548 typ host generation 0\r\na=ice-ufrag:rl/PIMG6Pd1h6Ymp\r\na=ice-pwd:jsymMG3rh3Fq1vK83jHyQVtt\r\na=ice-options:google-ice\r\na=fingerprint:sha-256 C0:F7:9C:63:AC:84:62:E9:0D:F5:3B:D9:F8:7E:53:29:E2:1F:44:41:84:D1:B6:D7:48:39:A5:64:1F:E7:B4:E4\r\na=extmap:2 urn:ietf:params:rtp-hdrext:toffset\r\na=sendrecv\r\na=mid:video\r\na=rtcp-mux\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:f4OO7dHJbCQsjecAC+0TFp6g6KBXyOub6yBmx+Xx\r\na=rtpmap:100 VP8/90000\r\na=rtcp-fb:100 ccm fir\r\na=rtcp-fb:100 nack \r\na=rtpmap:116 red/90000\r\na=rtpmap:117 ulpfec/90000\r\na=ssrc:3255638847 cname:XsXQR1VfOels9+3s\r\na=ssrc:3255638847 msid:mXFROJeVMQxDhCFH34Yukxots985y812wGPJ mXFROJeVMQxDhCFH34Yukxots985y812wGPJv0\r\na=ssrc:3255638847 mslabel:mXFROJeVMQxDhCFH34Yukxots985y812wGPJ\r\na=ssrc:3255638847 label:mXFROJeVMQxDhCFH34Yukxots985y812wGPJv0\r\n",
            chromeAudio: "v=0\r\no=- 2751679977 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE audio\r\na=msid-semantic: WMS YyMaveYaWtkfdWeZtSHs3AHFuH4TEYh4MZDh\r\nm=audio 63231 RTP/SAVPF 111 103 104 0 8 107 106 105 13 126\r\nc=IN IP4 192.67.4.11\r\na=rtcp:63231 IN IP4 192.67.4.11\r\na=candidate:521808905 1 udp 2113937151 192.67.4.11 63231 typ host generation 0\r\na=candidate:521808905 2 udp 2113937151 192.67.4.11 63231 typ host generation 0\r\na=ice-ufrag:1VZUXywcfSTmvPBK\r\na=ice-pwd:NHrjWPuvIlyBQD7UVw4zi/4F\r\na=ice-options:google-ice\r\na=fingerprint:sha-256 49:1E:A3:EB:78:C2:89:55:5D:0D:6E:F2:B7:41:50:DB:10:C4:B2:54:8F:D8:24:A5:E8:56:0A:56:F4:BA:3A:ED\r\na=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\na=sendrecv\r\na=mid:audio\r\na=rtcp-mux\r\na=crypto:0 AES_CM_128_HMAC_SHA1_32 inline:MpqMpDpEDjNDfpquFL8jIkO9oLp2Dp4NOYiSmrea\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:/yAvMdC0p1e/4c/Jc6ljepmHpIuHV9jO3FyrrTX4\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10\r\na=rtpmap:103 ISAC/16000\r\na=rtpmap:104 ISAC/32000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:107 CN/48000\r\na=rtpmap:106 CN/32000\r\na=rtpmap:105 CN/16000\r\na=rtpmap:13 CN/8000\r\na=rtpmap:126 telephone-event/8000\r\na=maxptime:60\r\na=ssrc:3334051080 cname:ECpt57S24HzaX1WY\r\na=ssrc:3334051080 msid:YyMaveYaWtkfdWeZtSHs3AHFuH4TEYh4MZDh YyMaveYaWtkfdWeZtSHs3AHFuH4TEYh4MZDha0\r\na=ssrc:3334051080 mslabel:YyMaveYaWtkfdWeZtSHs3AHFuH4TEYh4MZDh\r\na=ssrc:3334051080 label:YyMaveYaWtkfdWeZtSHs3AHFuH4TEYh4MZDha0\r\n",
            firefoxVideo: "v=0\r\no=Mozilla-SIPUA-24.0a1 12643 0 IN IP4 0.0.0.0\r\ns=SIP Call\r\nt=0 0\r\na=ice-ufrag:1a870bf3\r\na=ice-pwd:948d30c7fe15b95a7bd63743ae84ac2e\r\na=fingerprint:sha-256 1C:D2:EC:A0:51:89:35:BE:84:4B:BC:11:F3:D4:D6:C7:F7:39:52:C5:2D:55:88:1D:61:24:7A:54:20:8A:AE:C2\r\nm=audio 50859 RTP/SAVPF 109 0 8 101\r\nc=IN IP4 192.67.4.11\r\na=rtpmap:109 opus/48000/2\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=sendrecv\r\na=candidate:0 1 UDP 2113601791 192.67.4.11 50859 typ host\r\na=candidate:0 2 UDP 2113601790 192.67.4.11 53847 typ host\r\nm=video 62311 RTP/SAVPF 120\r\nc=IN IP4 192.67.4.11\r\na=rtpmap:120 VP8/90000\r\na=sendrecv\r\na=candidate:0 1 UDP 2113601791 192.67.4.11 62311 typ host\r\na=candidate:0 2 UDP 2113601790 192.67.4.11 54437 typ host\r\n",
            firefoxAudio: "v=0\r\no=Mozilla-SIPUA-24.0a1 20557 0 IN IP4 0.0.0.0\r\ns=SIP Call\r\nt=0 0\r\na=ice-ufrag:66600851\r\na=ice-pwd:aab7c3c8d881f6406eff1f1ff2e3bc5e\r\na=fingerprint:sha-256 C3:C4:98:95:D0:58:B1:D2:F9:72:A0:44:EB:C7:C4:49:95:8F:EE:00:05:10:82:A8:6E:F6:4A:DF:43:A3:2A:16\r\nm=audio 56026 RTP/SAVPF 109 0 8 101\r\nc=IN IP4 192.67.4.11\r\na=rtpmap:109 opus/48000/2\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=sendrecv\r\na=candidate:0 1 UDP 2113601791 192.67.4.11 56026 typ host\r\na=candidate:0 2 UDP 2113601790 192.67.4.11 56833 typ host\r\n",
        };

        for (s in SDP) {
            var bro = s;
            var bs = SDP[s];
            Phono.log.debug("testing " + s);
            var sdpObj = Phono.sdp.parseSDP(bs);
            Phono.log.debug(JSON.stringify(sdpObj, null, " "));

            var resultSDP = Phono.sdp.buildSDP(sdpObj);
            Phono.log.debug(s + " Resulting SDP:");
            Phono.log.debug(resultSDP);
        }

    }

}());
