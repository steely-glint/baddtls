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
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.List;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.json.JsonWriter;
import org.ice4j.ice.Candidate;

/**
 *
 * @author tim
 */
public class Connect extends HttpServlet {

    Hashtable ports = null;
    SecureRandom sec = new SecureRandom();

    @Override
    public void init() {
        Log.setLevel(Log.VERB);
        // ensure that all subclasses of this servlet share the same 'usedport' list
        ServletContext context = this.getServletContext();
        ports = (Hashtable) context.getAttribute("ports");
        if (ports == null) {
            ports = new Hashtable();
            context.setAttribute("ports", ports);
            Log.debug("Setting new ports hashtable");
        } else {
            Log.debug("using existing new ports hashtable");
        }
    }

    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        try (PrintWriter out = response.getWriter()) {
            /* TODO output your page here. You may use following sample code. */
            out.println("<!DOCTYPE html>");
            out.println("<html>");
            out.println("<head>");
            out.println("<title>Servlet Connect</title>");
            out.println("</head>");
            out.println("<body>");
            out.println("<h1>Servlet Connect at " + request.getContextPath() + "</h1>");
            out.println("</body>");
            out.println("</html>");
        }
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        IceConnect ic = null;
        Log.debug("In servlet (post)");
        String jsonData = "{}";
        response.setContentType("application/json");
        char[] body = new char[request.getContentLength()];
        Reader red = request.getReader();
        red.read(body);
        String sbody = new String(body);
        Log.debug("Got:" + sbody);
        StringReader s = new StringReader(sbody);
        JsonReader reader = Json.createReader(s);
        JsonObject message = (JsonObject) reader.read();
        int port = 0;
        Integer portI = null;
        int retries = 0;
        do {
            port = 15000 + sec.nextInt(1000);
            portI = new Integer(port);
            Log.debug("Port try :" + portI);
            retries++;
        } while (ports.containsKey(portI) && retries < 5);

        try {
            ic = new IceConnect(port);
            ports.put(portI, ic);
            final Integer portT = portI;
            Log.debug("Port using :" + portI);

            ic.cleanup = new Runnable() {
                public void run() {
                    Log.debug("Releasing port :" + portT);
                    ports.remove(portT);
                }
            };

        } catch (Exception ex) {
            Log.error("Exception in ice connector creation " + ex.getMessage());
            ex.printStackTrace();
        }

        // honestly - you look at this and you just wish for groovy or xpath to write this in a declarative way.
        if (message.containsKey("sdp")) {
            JsonObject sdpo = message.getJsonObject("sdp");
            JsonArray contents = sdpo.getJsonArray("contents");
            for (JsonValue content : contents) {
                JsonObject fpo = ((JsonObject) content).getJsonObject("fingerprint");
                if ("sha-256".equalsIgnoreCase(fpo.getString("hash"))) {
                    String ffp = fpo.getString("print");
                    ic.setFarFingerprint(ffp);
                }
                JsonObject media = ((JsonObject) content).getJsonObject("media");

                String proto = media.getString("proto");
                if ("DTLS/SCTP".equals(proto)) {
                    JsonObject ice = ((JsonObject) content).getJsonObject("ice");
                    String ufrag = ice.getString("ufrag");
                    String pass = ice.getString("pwd");
                    try {
                        ic.buildIce(ufrag, pass);
                    } catch (Exception ex) {
                        Log.error(ex.toString());
                    }
                    JsonArray candies = ((JsonObject) content).getJsonArray("candidates");
                    for (JsonValue v_candy : candies) {
                        JsonObject jcandy = (JsonObject) v_candy;
                        ic.addCandidate(jcandy.getString("foundation"), jcandy.getString("component"), jcandy.getString("protocol"), jcandy.getString("priority"), jcandy.getString("ip"), jcandy.getString("port"), jcandy.getString("type"));
                    }
                }
            }

            if (ic.getCandidates().size() > 0) {
                JsonObject answer = mkAnswer(ic);
                StringWriter stWriter = new StringWriter();
                try (JsonWriter jsonWriter = Json.createWriter(stWriter)) {
                    jsonWriter.writeObject(answer);
                }
                jsonData = stWriter.toString();
            } else {
                Log.debug("agh, no local candidates ");
            }
        }
        try (PrintWriter out = response.getWriter()) {
            Log.debug("Sending " + jsonData);
            out.write(jsonData);
        }
        ic.startIce();
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

    private JsonArrayBuilder mkCandidates(IceConnect ic) {
        JsonArrayBuilder ret = Json.createArrayBuilder();
        List<Candidate> candies = ic.getCandidates();
        //{"sdpMLineIndex":1,"sdpMid":"data","candidate":{"foundation":"2169522962","component":"1","protocol":"tcp","priority":"1509957375","ip":"192.67.4.33","port":"0","type":"host","generation":"0\r\n"}
        for (Candidate candy : candies) {
            ret.add(Json.createObjectBuilder()
                    .add("foundation", candy.getFoundation())
                    .add("component", candy.getParentComponent().getComponentID())
                    .add("protocol", candy.getTransport().toString())
                    .add("priority", candy.getPriority())
                    .add("ip", candy.getTransportAddress().getHostAddress())
                    .add("port", candy.getTransportAddress().getPort())
                    .add("type", candy.getType().toString())
                    .add("generation", "0")
            );
        }
        return ret;
    }

    private JsonObject mkAnswer(IceConnect ic) {
        JsonObject ans = Json.createObjectBuilder()
                .add("contents", Json.createArrayBuilder()
                        .add(Json.createObjectBuilder()
                                .add("candidates", mkCandidates(ic)
                                )
                                .add("codecs", Json.createArrayBuilder()
                                )
                                .add("ice", Json.createObjectBuilder()
                                        .add("ufrag", ic.getUfrag())
                                        .add("pwd", ic.getPass())
                                )
                                .add("media", Json.createObjectBuilder()
                                        .add("type", "application")
                                        .add("port", "1")
                                        .add("proto", "DTLS/SCTP")
                                        .add("sctpmap", Json.createArrayBuilder().add("5000"))
                                        .add("pts", Json.createArrayBuilder().add("5000"))
                                )
                                .add("connection", Json.createObjectBuilder()
                                        .add("nettype", "IN")
                                        .add("addrtype", "IP4")
                                        .add("address", "0.0.0.0")
                                )
                                .add("fingerprint", Json.createObjectBuilder()
                                        .add("hash", "sha-256")
                                        .add("print", ic.getPrint())
                                        .add("required", "1")
                                )
                                .add("mid", "data")
                                .add("setup", "passive")
                        )
                )
                .add("session", Json.createObjectBuilder()
                        .add("username", "-")
                        .add("id", "4648475892259889561")
                        .add("ver", "2")
                        .add("nettype", "IN")
                        .add("addrtype", "IP4")
                        .add("address", "127.0.0.1")
                )
                .build();
        return ans;
    }
}
