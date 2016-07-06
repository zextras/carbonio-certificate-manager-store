/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2011, 2013, 2014 Zimbra, Inc.
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
import java.util.Map;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.CertMgrConstants;
import com.zimbra.common.soap.Element;
import com.zimbra.common.util.ByteUtil;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.service.FileUploadServlet;
import com.zimbra.cs.service.FileUploadServlet.Upload;
import com.zimbra.cs.service.admin.AdminDocumentHandler;
import com.zimbra.soap.ZimbraSoapContext;

public class UploadDomCert extends AdminDocumentHandler {

    @Override
    public Element handle(Element request, Map<String, Object> context) throws ServiceException {
        ZimbraSoapContext lc = getZimbraSoapContext(context);
        Element response = lc.createElement(CertMgrConstants.UPLOAD_DOMCERT_RESPONSE);

        String attachId = null;
        String filename = null;
        Upload up = null ;

        try {
            attachId = request.getAttribute(CertMgrConstants.A_CERT_AID) ;
            filename = request.getAttribute(CertMgrConstants.A_CERT_NAME) ;
            ZimbraLog.security.debug("Found certificate Filename  = " + filename + "; attid = " + attachId );

            up = FileUploadServlet.fetchUpload(lc.getAuthtokenAccountId(), attachId, lc.getAuthToken());
            if (up == null)
                throw ServiceException.FAILURE("Uploaded file " + filename + " with " + attachId + " was not found.", null);

            byte [] blob = ByteUtil.getContent(up.getInputStream(),-1) ;
            if(blob.length > 0)
                response.addAttribute(CertMgrConstants.A_cert_content, new String(blob));
        }catch (IOException ioe) {
            throw ServiceException.FAILURE("Can not get uploaded certificate content", ioe);
        }finally {
            FileUploadServlet.deleteUpload(up);
        }

        try {
            attachId = request.getAttribute(CertMgrConstants.A_KEY_AID);
            filename = request.getAttribute(CertMgrConstants.A_KEY_NAME);
            ZimbraLog.security.debug("Found certificate Filename  = " + filename + "; attid = " + attachId );

            up = FileUploadServlet.fetchUpload(lc.getAuthtokenAccountId(), attachId, lc.getAuthToken());
            if (up == null)
                throw ServiceException.FAILURE("Uploaded file " + filename + " with " + attachId + " was not found.", null);

            byte [] blob = ByteUtil.getContent(up.getInputStream(),-1) ;
            if(blob.length > 0)
                response.addAttribute(CertMgrConstants.A_key_content, new String(blob));
        }catch (IOException ioe) {
            throw ServiceException.FAILURE("Can not get uploaded key content", ioe);
        }finally {
            FileUploadServlet.deleteUpload(up);
        }

        return response;
    }
}
