/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014 Zimbra, Inc.
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
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import com.zimbra.common.account.Key.ServerBy;
import com.zimbra.common.localconfig.LC;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.AdminConstants;
import com.zimbra.common.soap.CertMgrConstants;
import com.zimbra.common.soap.Element;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.Server;
import com.zimbra.cs.account.accesscontrol.AdminRight;
import com.zimbra.cs.account.accesscontrol.Rights.Admin;
import com.zimbra.cs.rmgmt.RemoteManager;
import com.zimbra.cs.rmgmt.RemoteResult;
import com.zimbra.cs.service.admin.AdminDocumentHandler;
import com.zimbra.soap.ZimbraSoapContext;


public class GetCSR extends AdminDocumentHandler {
    private final static String CSR_TYPE_SELF = "self" ;
    private final static String CSR_TYPE_COMM = "comm" ;
    static final String KEY_SUBJECT = "subject" ;
    static final String KEY_SUBJECT_ALT_NAME = "SubjectAltName";
    private final static String CSR_FILE = LC.zimbra_home.value() + "/ssl/zimbra/server/server.csr" ;
    @Override
    public Element handle(Element request, Map<String, Object> context) throws ServiceException {
        ZimbraSoapContext lc = getZimbraSoapContext(context);
        
        Provisioning prov = Provisioning.getInstance();
        
        Server server = null;
        String serverId = request.getAttribute(AdminConstants.A_SERVER) ;
    	if (serverId != null && serverId.equals(ZimbraCertMgrExt.ALL_SERVERS)) {
        	server = prov.getLocalServer() ;
        }else { 
        	server = prov.get(ServerBy.id, serverId);
        }
        
        if (server == null) {
            throw ServiceException.INVALID_REQUEST("Server with id " + serverId + " could not be found", null);
        }
        checkRight(lc, context, server,Admin.R_getCSR);
        ZimbraLog.security.debug("load the CSR info from server:  " + server.getName()) ;
        
        
        String cmd = ZimbraCertMgrExt.GET_CSR_CMD ;
        String type = request.getAttribute(AdminConstants.A_TYPE) ;
        if (type == null || type.length() == 0 ) {
            throw ServiceException.INVALID_REQUEST("No valid CSR type is set.", null);
        }else if (type.equals(CSR_TYPE_SELF) || type.equals(CSR_TYPE_COMM)) {
            cmd += " " + type ;
        }else{
            throw ServiceException.INVALID_REQUEST("Invalid CSR type: " + type +". Must be (self|comm).", null);    
        }
        
        Element response = lc.createElement(CertMgrConstants.GET_CSR_RESPONSE);
        String csr_exists = "0" ;
        String isComm = "0" ;
        if (type.equals(CSR_TYPE_COMM)) {
            isComm = "1" ;
        }
        
        RemoteManager rmgr = RemoteManager.getRemoteManager(server);
        ZimbraLog.security.debug("***** Executing the cmd = " + cmd) ;
        RemoteResult rr = null;
        try {
            rr = rmgr.execute(cmd);
            HashMap <String, String> output = OutputParser.parseOuput(rr.getMStdout()) ;
            HashMap <String, String> subjectDSN = null ;
            Vector <String> subjectAltNames = null ;
            
            for (String k: output.keySet()) {
                if (k.equals(KEY_SUBJECT)) {
                    subjectDSN = OutputParser.parseSubject(output.get(k)) ;
                }else if (k.equals(KEY_SUBJECT_ALT_NAME)) {
                    subjectAltNames = OutputParser.parseSubjectAltName(output.get(k));
                }
            }
            
            if (subjectDSN != null) {
                for (String k: subjectDSN.keySet()) {
                    Element el = response.addElement(k);
                    el.setText(subjectDSN.get(k));
                }
                
                if (subjectAltNames != null && (!subjectAltNames.isEmpty())) {
                    for (Enumeration<String> e = subjectAltNames.elements(); e.hasMoreElements();) {
                        Element el = response.addElement(CertMgrConstants.E_SUBJECT_ALT_NAME);
                        String value = e.nextElement();
                        //ZimbraLog.security.info("Add the SubjectAltNames element " + value);
                        el.setText(value) ;
                    }
                }
            
                csr_exists = "1" ;
            }
            
        } catch (ServiceException e) {
            //No CSR Found. Just return an empty response.
            //so the error won't be thrown
            ZimbraLog.security.warn(e);
         } catch (IOException ioe) {
            throw ServiceException.FAILURE("exception occurred handling command", ioe);
        }
         
        response.addAttribute(CertMgrConstants.A_csr_exists, csr_exists) ;
        response.addAttribute(CertMgrConstants.A_isComm, isComm) ;
        response.addAttribute(AdminConstants.A_SERVER, server.getName());
        return response ;
    }
    
    @Override
    public void docRights(List<AdminRight> relatedRights, List<String> notes) {
    	 relatedRights.add(Admin.R_getCSR);
    }
}
