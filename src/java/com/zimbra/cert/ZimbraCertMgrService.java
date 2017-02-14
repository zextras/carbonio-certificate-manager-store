/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2007, 2008, 2009, 2010, 2011, 2013, 2014, 2016 Synacor, Inc.
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

import com.zimbra.common.soap.CertMgrConstants;
import com.zimbra.soap.DocumentDispatcher;
import com.zimbra.soap.DocumentService;


public class ZimbraCertMgrService implements DocumentService {

    public void registerHandlers(DocumentDispatcher dispatcher) {
        dispatcher.registerHandler(CertMgrConstants.INSTALL_CERT_REQUEST, new InstallCert());
        dispatcher.registerHandler(CertMgrConstants.GET_CERT_REQUEST, new GetCert());
        dispatcher.registerHandler(CertMgrConstants.GEN_CSR_REQUEST, new GenerateCSR());
        dispatcher.registerHandler(CertMgrConstants.GET_CSR_REQUEST, new GetCSR());
	    dispatcher.registerHandler(CertMgrConstants.VERIFY_CERTKEY_REQUEST, new VerifyCertKey());
        dispatcher.registerHandler(CertMgrConstants.UPLOAD_DOMCERT_REQUEST, new UploadDomCert());
        dispatcher.registerHandler(CertMgrConstants.UPLOAD_PROXYCA_REQUEST, new UploadProxyCA());
    }
}
