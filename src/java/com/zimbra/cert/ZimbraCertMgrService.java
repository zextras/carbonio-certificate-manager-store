// SPDX-FileCopyrightText: 2022 Synacor, Inc.
// SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
//
// SPDX-License-Identifier: GPL-2.0-only

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
