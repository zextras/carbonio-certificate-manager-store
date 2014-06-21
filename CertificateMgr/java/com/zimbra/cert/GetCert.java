/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2007, 2008, 2009, 2010, 2011, 2012, 2013 Zimbra, Inc.
 * 
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */
package com.zimbra.cert;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.AdminConstants;
import com.zimbra.common.soap.CertMgrConstants;
import com.zimbra.common.soap.Element;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.Server;
import com.zimbra.common.account.Key.ServerBy;
import com.zimbra.cs.account.accesscontrol.AdminRight;
import com.zimbra.cs.account.accesscontrol.Rights.Admin;
import com.zimbra.cs.rmgmt.RemoteManager;
import com.zimbra.cs.rmgmt.RemoteResult;
import com.zimbra.cs.service.admin.AdminDocumentHandler;
import com.zimbra.soap.ZimbraSoapContext;


public class GetCert extends AdminDocumentHandler {
    final static String CERT_TYPE_STAGED= "staged" ;
    final static String CERT_TYPE_ALL = "all" ;
    final static String [] CERT_TYPES = {"ldap", "mailboxd", "mta", "proxy"};
    final static String CERT_STAGED_OPTION_SELF = "self" ;
    final static String CERT_STAGED_OPTION_COMM = "comm" ;
    
    @Override
    public Element handle(Element request, Map<String, Object> context) throws ServiceException{
        ZimbraSoapContext lc = getZimbraSoapContext(context);

        Provisioning prov = Provisioning.getInstance();
        ArrayList<Server> servers = new ArrayList<Server>();
        String serverId = request.getAttribute(AdminConstants.A_SERVER) ;
        String certType = request.getAttribute(AdminConstants.A_TYPE);
        String option = null;
        if (certType.equals(CERT_TYPE_STAGED)) {
            option = request.getAttribute(CertMgrConstants.A_OPTION);
        }
        if (serverId != null && serverId.equals(ZimbraCertMgrExt.ALL_SERVERS)) {
            servers.addAll(prov.getAllServers());
        }else {
           Server server =  prov.get(ServerBy.id, serverId);
           if (server != null) {
               servers.add(server);
           } else {
               throw ServiceException.INVALID_REQUEST("Server with id " + serverId + " could not be found", null);
           }
        }
       
        Element response = lc.createElement(CertMgrConstants.GET_CERT_RESPONSE);
        
        for (Server s: servers) {
            addCertsOnServer(response, s, certType, option, context, lc);
        }
        
        return response;
 
    }
    
    private void addCertsOnServer(Element response, Server server,
            String certType, String option, Map<String, Object> context,
            ZimbraSoapContext lc) throws ServiceException {
        
        checkRight(lc, context, server, Admin.R_getCertificateInfo);
        ZimbraLog.security.debug("load the cert info from server:  " + server.getName()) ;
        
        String cmd = "";
        try {
            RemoteManager rmgr = RemoteManager.getRemoteManager(server);
            
            if (certType == null || certType.length() == 0 ) {
                throw ServiceException.INVALID_REQUEST("No valid certificate type is set in GetCertRequest", null);
            }else if (certType.equals(CERT_TYPE_STAGED)){ 
               
                if (option == null || option.length() ==0) {
                    throw ServiceException.INVALID_REQUEST("No valid option type is set in GetCertRequest for staged certs", null);
                }else if (option.equals(CERT_STAGED_OPTION_SELF) || option.equals(CERT_STAGED_OPTION_COMM)){
                    cmd = ZimbraCertMgrExt.GET_STAGED_CERT_CMD + " " + option;
                    ZimbraLog.security.debug("***** Executing the cmd = " + cmd) ;
                    addCertInfo(response, rmgr.execute(cmd), certType, server.getName()) ;
                }else{
                    throw ServiceException.INVALID_REQUEST(
                           "Invalid option is set in GetCertRequest for staged certs: " 
                           + certType + ". Must be (self|comm).", null); 
                }
            }else if (certType.equals(CERT_TYPE_ALL)){
                for (int i=0; i < CERT_TYPES.length; i ++) {
                    cmd = ZimbraCertMgrExt.GET_DEPLOYED_CERT_CMD + " " + CERT_TYPES[i] ;
                    ZimbraLog.security.debug("***** Executing the cmd = " + cmd) ;
                    addCertInfo(response, rmgr.execute(cmd), CERT_TYPES[i], server.getName()) ;
                }
            }else if (Arrays.asList(CERT_TYPES).contains(certType)){
                    //individual types
                cmd = ZimbraCertMgrExt.GET_DEPLOYED_CERT_CMD + " " + certType;
                ZimbraLog.security.debug("***** Executing the cmd = " + cmd) ;
                addCertInfo(response, rmgr.execute(cmd), certType, server.getName()) ;
            }else{
                throw ServiceException.INVALID_REQUEST("Invalid certificate type: " + certType + ". Must be (self|comm).", null);
            }
        }catch (IOException ioe) {
            throw ServiceException.FAILURE("exception occurred handling command", ioe);
        }
    }
    
    public void addCertInfo(Element parent, RemoteResult rr, String certType, String serverName) throws ServiceException, IOException{
        try {
            byte[] stdOut = rr.getMStdout() ;
            HashMap <String, String> output = OutputParser.parseOuput(stdOut) ;
            Element el = parent.addElement(CertMgrConstants.E_cert);
            el.addAttribute(AdminConstants.A_TYPE, certType);
            el.addAttribute(AdminConstants.A_SERVER, serverName);
            for (String k: output.keySet()) {
                ZimbraLog.security.debug("Adding element " + k + " = " + output.get(k)) ;
                Element certEl = el.addElement(k);
                certEl.setText(output.get(k));
            }
        }catch(ServiceException e) {
            ZimbraLog.security.warn ("Failed to retrieve the certificate information for " + certType + ".");
            ZimbraLog.security.error(e) ;
        }
    }
    
    @Override
    public void docRights(List<AdminRight> relatedRights, List<String> notes) {
        relatedRights.add(Admin.R_getCertificateInfo);
    }
}
