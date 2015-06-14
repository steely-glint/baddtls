function IpseDataChannel(mode) {
    var mode = mode;
    var send = function(mod, data) {
        console.log("send " + data);
        $.post(mod, data).done(
                function(ans) {
                    console.log("got " + JSON.stringify(ans));
                    onAnswer(ans);
                });
    };
    var onAnswer = function(data) {
        if (data.session) {
            var sdp = Phono.sdp.buildSDP(data);
            console.log("answer sdp is " + sdp);
            var message = {'sdp': sdp, 'type': 'answer'};
            var rtcd = new RTCSessionDescription(message);
            console.log("rtcd is " + rtcd);
            pc.setRemoteDescription(rtcd, function() {
                console.log("set answer ok");
            }, logError);
        } else {
            console.log("no session in my data");
        }
    };
    var logError = function(error) {
        console.log(error.name + ": " + error.message);
    };
    var configuration = {"iceServers": [
            {url: "stun:stun.l.google.com:19302"}//,
        ]};
    var pc;
    if (typeof webkitRTCPeerConnection == "function") {
        pc = new webkitRTCPeerConnection(configuration, null);
    } else if (typeof mozRTCPeerConnection == "function") {
        pc = mozRTCPeerConnection(configuration, null);
    }

// send any ice candidates to the other peer
    pc.onicecandidate = function(evt) {
        if (evt.candidate === null) {
            var sdpObj = Phono.sdp.parseSDP(pc.localDescription.sdp);
            var sdpcontext = {"type": pc.localDescription.type, "sdp": sdpObj};
            send(mode, JSON.stringify(sdpcontext));
        } else {
            console.log("ignoring local trickling candidates for now")
        }
    };
    // let the "negotiationneeded" event trigger offer generation
    pc.onnegotiationneeded = function() {
        var sdpConstraints = {'mandatory': {'OfferToReceiveAudio': false, 'OfferToReceiveVideo': false}}
        pc.createOffer(function(desc) {
            pc.setLocalDescription(desc, function() {
                console.log("Set Local description");
            }, this.logError);
        }, this.logError, sdpConstraints);
    }
    this.peerCon = pc;
}

IpseDataChannel.prototype.setOnDataChannel = function(callback) {
    this.peerCon.ondatachannel = function(evt) {
        evt.channel;
        callback(evt.channel);
    };
}
IpseDataChannel.prototype.createDataChannel = function(name, props) {
    return this.peerCon.createDataChannel(name, props)
}


