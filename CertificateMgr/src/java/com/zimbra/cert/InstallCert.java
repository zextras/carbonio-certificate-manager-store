/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2007, 2008, 2009, 2010, 2011, 2013, 2014 Zimbra, Inc.
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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

import com.google.common.base.Strings;
import com.zimbra.common.account.Key.ServerBy;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.AdminConstants;
import com.zimbra.common.soap.CertMgrConstants;
import com.zimbra.common.soap.Element;
import com.zimbra.common.util.ByteUtil;
import com.zimbra.common.util.StringUtil;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.Server;
import com.zimbra.cs.account.accesscontrol.AdminRight;
import com.zimbra.cs.account.accesscontrol.Rights.Admin;
import com.zimbra.cs.rmgmt.RemoteManager;
import com.zimbra.cs.rmgmt.RemoteResult;
import com.zimbra.cs.service.FileUploadServlet;
import com.zimbra.cs.service.FileUploadServlet.Upload;
import com.zimbra.cs.service.admin.AdminDocumentHandler;
import com.zimbra.soap.JaxbUtil;
import com.zimbra.soap.ZimbraSoapContext;
import com.zimbra.soap.admin.message.InstallCertRequest;
import com.zimbra.soap.admin.type.AidAndFilename;
import com.zimbra.soap.admin.type.CommCert;

public class InstallCert extends AdminDocumentHandler {
    final static String CERT_TYPE_SELF= "self" ;
    final static String CERT_TYPE_COMM = "comm" ;
    private final static String ALLSERVER_FLAG = "-allserver" ;
    private Server server = null;

    private Provisioning prov = null;

    @Override
    public Element handle(Element request, Map<String, Object> context) throws ServiceException {
        ZimbraSoapContext lc = getZimbraSoapContext(context);

        prov = Provisioning.getInstance();
        InstallCertRequest req = JaxbUtil.elementToJaxb(request);

        String serverId = req.getServer();
        boolean isTargetAllServer = false ;
        if (serverId != null && serverId.equals(ZimbraCertMgrExt.ALL_SERVERS)) {
            server = prov.getLocalServer() ;
            isTargetAllServer = true ;
        }else {
            server = prov.get(ServerBy.id, serverId);
        }

        if (server == null) {
            throw ServiceException.INVALID_REQUEST("Server with id " + serverId + " could not be found", null);
        }
        checkRight(lc, context, server, Admin.R_installCertificate);
        ZimbraLog.security.debug("Install the certificateion for server: %s", server.getName()) ;
        //the deployment of certs should happen on the target server
        RemoteManager rmgr = RemoteManager.getRemoteManager(server);
        StringBuilder cmd = new StringBuilder(ZimbraCertMgrExt.CREATE_CRT_CMD);
        StringBuilder deploycrt_cmd = new StringBuilder(ZimbraCertMgrExt.DEPLOY_CERT_CMD);
        String certType = req.getType();
        if (Strings.isNullOrEmpty(certType)) {
            throw ServiceException.INVALID_REQUEST("No valid certificate type is set", null);
        }else if (certType.equals(CERT_TYPE_SELF) || certType.equals(CERT_TYPE_COMM)) {
            deploycrt_cmd.append(" ").append(certType);
        }else {
            throw ServiceException.INVALID_REQUEST("Invalid certificate type: " + certType + ". Must be (self|comm).",
                    null);
        }

        if (certType.equals("comm")) {
            checkUploadedCommCert(req, lc, isTargetAllServer) ;
        }

        //always set the -new flag for the cmd since the ac requests for a new cert always
        cmd.append(" -new");

        if (!certType.equals("comm")) {
            String validation_days = req.getValidationDays();
            if (!Strings.isNullOrEmpty(validation_days)) {
                if (!validation_days.matches("[0-9]*")) {
                    throw ServiceException.INVALID_REQUEST(String.format(
                            "validation_days %s is not valid.", validation_days), null);
                }
                cmd.append(" -days ").append(validation_days);
            }
        }

        String subject = GenerateCSR.getSubject(req.getSubject()) ;

        String subjectAltNames = GenerateCSR.getSubjectAltNames(req.getSubjectAltNames());

        if (certType.equals("self")) {
            String digest = req.getDigest();
            if (Strings.isNullOrEmpty(digest)) {
                digest = "sha1";
            } else if (!digest.matches("[a-zA-z0-9]*")) {
                throw ServiceException.INVALID_REQUEST("digest is not valid.", null);
            }
            cmd.append(" -digest ").append(digest);

            String keysize = req.getKeySize();
            if (!"1024".equals(keysize)) {
                keysize = "2048";
            }
            cmd.append(" -keysize ").append(keysize);

            GenerateCSR.appendSubjectArgToCommand(cmd, subject);

            if (subjectAltNames != null && subjectAltNames.length() >0) {
                cmd.append(" -subjectAltNames \"").append(subjectAltNames).append("\"");
            }
        } else if (certType.equals("comm")) {
            deploycrt_cmd.append(" ").append(ZimbraCertMgrExt.UPLOADED_CRT_FILE).append(" ")
                .append(ZimbraCertMgrExt.UPLOADED_CRT_CHAIN_FILE);
        }

        if (isTargetAllServer) {
           if (certType.equals("self")) { //self -allserver install - need to pass the subject to the createcrt cmd
                if (subject != null && subject.length() > 0) {
                    ZimbraLog.security.debug("Subject for allserver: %s", subject);
                    GenerateCSR.appendSubjectArgToCommand(cmd, subject);
                }
            }

            cmd.append(" ").append(ALLSERVER_FLAG);
            deploycrt_cmd.append(" ").append(ALLSERVER_FLAG);
        }

        RemoteResult rr ;
        if (certType.equals("self")) {
            ZimbraLog.security.debug("***** Executing the cmd = %s", cmd) ;
            rr = rmgr.execute(cmd.toString());
            //ZimbraLog.security.info("***** Exit Status Code = " + rr.getMExitStatus()) ;
            try {
                OutputParser.parseOuput(rr.getMStdout()) ;
            }catch (IOException ioe) {
                throw ServiceException.FAILURE("exception occurred handling command", ioe);
            }
        }

        //need to deploy the crt now
        ZimbraLog.security.debug("***** Executing the cmd = %s", deploycrt_cmd) ;
        rr = rmgr.execute(deploycrt_cmd.toString());
        try {
            OutputParser.parseOuput(rr.getMStdout()) ;
        }catch (IOException ioe) {
            throw ServiceException.FAILURE("exception occurred handling command", ioe);
        }

        Element response = lc.createElement(CertMgrConstants.INSTALL_CERT_RESPONSE);
        response.addAttribute(AdminConstants.A_SERVER, server.getName());
        return response;
    }


    private boolean checkUploadedCommCert (InstallCertRequest req, ZimbraSoapContext lc, boolean isAllServer)
    throws ServiceException {
        Upload up = null ;
        InputStream is = null ;
        //the verification commands are all executed on the local server
        RemoteManager rmgr = RemoteManager.getRemoteManager(prov.getLocalServer());

        try {
            //read the cert file
            ByteArrayOutputStream completeCertChain = new ByteArrayOutputStream(8192);
            CommCert commCert = req.getCommCert();
            if (null == commCert) {
                throw ServiceException.INVALID_REQUEST("commCert element could not be found", null);
            }
            AidAndFilename certInfo = commCert.getCert();
            if (null == certInfo) {
                throw ServiceException.INVALID_REQUEST("comm_cert/cert element could not be found", null);
            }
            String attachId = certInfo.getAttachmentId();
            String filename = certInfo.getFilename();
            ZimbraLog.security.debug("Certificate Filename  = %s; attid = %s", filename, attachId);

            up = FileUploadServlet.fetchUpload(lc.getAuthtokenAccountId(), attachId, lc.getAuthToken());
            if (up == null) {
                throw ServiceException.FAILURE("Uploaded file " + filename + " with " + attachId + " was not found.",
                        null);
            }

            is = up.getInputStream() ;
            byte [] cert = ByteUtil.getContent(is, 1024) ;
            ZimbraLog.security.debug ("Put the uploaded commercial crt  to " + ZimbraCertMgrExt.UPLOADED_CRT_FILE) ;
            ByteUtil.putContent(ZimbraCertMgrExt.UPLOADED_CRT_FILE, cert) ;
            is.close();
            completeCertChain.write(cert);
            completeCertChain.write('\n') ;

            //read the CA
            ByteArrayOutputStream baos = new ByteArrayOutputStream(8192);

            AidAndFilename rootCAinfo = commCert.getRootCA();
            attachId = rootCAinfo.getAttachmentId();
            filename = rootCAinfo.getFilename();

            ZimbraLog.security.debug("Certificate Filename  = %s; attid = %s", filename, attachId);

            up = FileUploadServlet.fetchUpload(lc.getAuthtokenAccountId(), attachId, lc.getAuthToken());
            if (up == null) {
                throw ServiceException.FAILURE("Uploaded file " + filename + " with " + attachId + " was not found.",
                        null);
            }
            is = up.getInputStream();
            byte [] rootCA = ByteUtil.getContent(is, 1024) ;
            is.close();

            //read interemediateCA
            byte [] intermediateCA ;
            List<AidAndFilename> intermediateCAlist = commCert.getIntermediateCAs();
            if (null != intermediateCAlist) {
                for (AidAndFilename info : intermediateCAlist) {
                    attachId = info.getAttachmentId();
                    filename = info.getFilename();

                    if (attachId != null && filename != null) {
                        ZimbraLog.security.debug("Certificate Filename  = %s; attid = %s", filename, attachId );

                        up = FileUploadServlet.fetchUpload(lc.getAuthtokenAccountId(), attachId, lc.getAuthToken());
                        if (up == null)
                            throw ServiceException.FAILURE("Uploaded file " + filename + " with " +
                                    attachId + " was not found.", null);
                        is = up.getInputStream();
                        intermediateCA = ByteUtil.getContent(is, 1024);
                        is.close();

                        baos.write(intermediateCA);
                        baos.write('\n');

                        completeCertChain.write(intermediateCA);
                        completeCertChain.write('\n');
                    }
                }
            }

            baos.write(rootCA);
            baos.write('\n');


            byte [] chain = baos.toByteArray() ;
            baos.close();

            completeCertChain.write(rootCA);
            completeCertChain.write('\n');
            completeCertChain.close();

            ZimbraLog.security.debug ("Put the uploaded crt chain  to " + ZimbraCertMgrExt.UPLOADED_CRT_CHAIN_FILE) ;
            ByteUtil.putContent(ZimbraCertMgrExt.UPLOADED_CRT_CHAIN_FILE, chain) ;

            String privateKey = null;
            if (isAllServer) {
                ZimbraLog.security.debug ("Retrieving zimbraSSLPrivateKey from Global Config.");
                privateKey = prov.getConfig().getAttr(ZimbraCertMgrExt.A_zimbraSSLPrivateKey);
                //Note: We do this because zmcertmgr don't save the private key to global config
                //since -allserver is not supported by createcsr
                // and deploycrt has to take the hard path of cert and CA chain
                if (privateKey == null || privateKey.length() <= 0) {
                    //permission is denied for the  COMM_CRT_KEY_FILE which is readable to root only
                    //ZimbraLog.security.debug ("Retrieving commercial private key from " + ZimbraCertMgrExt.COMM_CRT_KEY_FILE);
                    //privateKey = new String (ByteUtil.getContent(new File(ZimbraCertMgrExt.COMM_CRT_KEY_FILE))) ;

                    //retrieve the key from the local server  since the key is always saved in the local server when createcsr is called
                    ZimbraLog.security.debug ("Retrieving zimbraSSLPrivateKey from server: " + server.getName());
                    privateKey = server.getAttr(ZimbraCertMgrExt.A_zimbraSSLPrivateKey) ;
                }
            } else {
                ZimbraLog.security.debug ("Retrieving zimbraSSLPrivateKey from server: " + server.getName());
                privateKey = server.getAttr(ZimbraCertMgrExt.A_zimbraSSLPrivateKey) ;
            }

            if (privateKey != null && privateKey.length() > 0) {
                ZimbraLog.security.debug ("Saving zimbraSSLPrivateKey to  " + ZimbraCertMgrExt.SAVED_COMM_KEY_FROM_LDAP) ;
            }   else {
                 throw ServiceException.FAILURE("zimbraSSLPrivateKey is not present.", new Exception());
            }
            ByteUtil.putContent(ZimbraCertMgrExt.SAVED_COMM_KEY_FROM_LDAP, privateKey.getBytes());

            try {
                //run zmcertmgr verifycrt to validate the cert and key
                String cmd = ZimbraCertMgrExt.VERIFY_CRTKEY_CMD + " comm "
                            //+ " " + ZimbraCertMgrExt.COMM_CRT_KEY_FILE
                            + " " + ZimbraCertMgrExt.SAVED_COMM_KEY_FROM_LDAP
                            + " " + ZimbraCertMgrExt.UPLOADED_CRT_FILE ;

                String verifychaincmd = ZimbraCertMgrExt.VERIFY_CRTCHAIN_CMD
                            + " " + ZimbraCertMgrExt.UPLOADED_CRT_CHAIN_FILE
                            + " " + ZimbraCertMgrExt.UPLOADED_CRT_FILE ;


                ZimbraLog.security.debug("*****  Executing the cmd: " + cmd);
                RemoteResult rr = rmgr.execute(cmd) ;

                OutputParser.parseOuput(rr.getMStdout()) ;

                //run zmcertmgr verifycrtchain to validate the certificate chain
                ZimbraLog.security.debug("*****  Executing the cmd: " + verifychaincmd);
                rr = rmgr.execute(verifychaincmd) ;
                OutputParser.parseOuput(rr.getMStdout()) ;

                //Certs are validated and Save the uploaded certificate to the LDAP
                String [] zimbraSSLCertificate =  {
                        ZimbraCertMgrExt.A_zimbraSSLCertificate, completeCertChain.toString()};

                ZimbraLog.security.debug("Save complete cert chain to " +  ZimbraCertMgrExt.A_zimbraSSLCertificate +
                    completeCertChain.toString()) ;

                if (isAllServer) {
                    prov.modifyAttrs(prov.getConfig(),
                        StringUtil.keyValueArrayToMultiMap(zimbraSSLCertificate, 0), true);
                }   else {
                    prov.modifyAttrs(server,
                        StringUtil.keyValueArrayToMultiMap(zimbraSSLCertificate, 0), true);
                }


            }catch (IOException ioe) {
                throw ServiceException.FAILURE("IOException occurred while running cert verification command", ioe);
            }
        } catch (IOException ioe) {
            throw ServiceException.FAILURE("IOException while handling uploaded certificate", ioe);
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException ioe) {
                    ZimbraLog.security.warn("exception closing uploaded certificate:", ioe);
                }
            }

            //delete the key file
            File comm_priv = new File (ZimbraCertMgrExt.SAVED_COMM_KEY_FROM_LDAP)  ;
            if (!comm_priv.delete()) {
                ZimbraLog.security.error ("File " + ZimbraCertMgrExt.SAVED_COMM_KEY_FROM_LDAP + " was not deleted");
            }
        }


        return true ;
    }

    @Override
    public void docRights(List<AdminRight> relatedRights, List<String> notes) {
        relatedRights.add(Admin.R_installCertificate);
    }
}
