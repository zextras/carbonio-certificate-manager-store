// SPDX-FileCopyrightText: 2022 Synacor, Inc.
// SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
//
// SPDX-License-Identifier: GPL-2.0-only

package com.zimbra.cert;

import com.zimbra.cert.util.ProcessStarter;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.CertMgrConstants;
import com.zimbra.common.soap.Element;
import com.zimbra.common.util.ByteUtil;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.ldap.LdapUtil;
import com.zimbra.cs.service.admin.AdminDocumentHandler;
import com.zimbra.soap.ZimbraSoapContext;
import java.io.File;
import java.io.IOException;
import java.util.Map;
import org.apache.commons.lang.StringUtils;

/**
 * Verifies provided private key and certificate against the server using zmcertmgr verifycrt.
 * It also verifies the chain certificate as it was issued by this server itself.
 */
public class VerifyCertKey extends AdminDocumentHandler {

  final static String VERIFY_CERT_COMMAND = "verifycrt";
  final static String CERT_MGR = "/opt/zextras/bin/zmcertmgr";
  final static String CERT_TYPE_COMM = "comm";

  private final ProcessStarter processStarter;
  private final String baseOperationPath;

  public VerifyCertKey(ProcessStarter baseProcess, String baseOperationPath) {
    this.processStarter = baseProcess;
    this.baseOperationPath = baseOperationPath;
  }

  @Override
  public Element handle(Element request, Map<String, Object> context) throws ServiceException {
    ZimbraSoapContext lc = getZimbraSoapContext(context);
    String certBuffer = request.getAttribute(CertMgrConstants.E_cert);
    String pvtKeyBuffer = request.getAttribute(CertMgrConstants.A_privkey);
    Element response = lc.createElement(CertMgrConstants.VERIFY_CERTKEY_RESPONSE);
    boolean verifyResult = false;
    final String keyFile = baseOperationPath + ZimbraCertMgrExt.COMM_CRT_KEY_FILE_NAME;
    final String certFile = baseOperationPath + ZimbraCertMgrExt.COMM_CRT_FILE_NAME;
    final String caFile = baseOperationPath + ZimbraCertMgrExt.COMM_CRT_CA_FILE_NAME;

    try {
      // replace the space character with '\n'
      String sanitizedCrt = formatWithNewLine(certBuffer);
      String sanitizedPvtKey = formatWithNewLine(pvtKeyBuffer);

      if (sanitizedCrt.length() == 0 || sanitizedPvtKey.length() == 0) {
        response.addAttribute(CertMgrConstants.A_verifyResult, "invalid");
        return response;
      }

      // store pvt key, crt and ca in a temporary file
      byte[] crtBytes = sanitizedCrt.getBytes();
      byte[] pvtKeyBytes = sanitizedPvtKey.getBytes();

      final String tmpPath = baseOperationPath + LdapUtil.generateUUID() + File.separator;
      File comm_path = new File(tmpPath);
      if (!comm_path.exists()) {
        if (!comm_path.mkdirs()) {
          throw ServiceException.FAILURE(
              "Cannot create dir " + comm_path.getAbsolutePath(), null);
        }
      } else if (!comm_path.isDirectory()) {
        throw ServiceException.FAILURE(
            "Path is not a directory: " + comm_path.getAbsolutePath(),
            null);
      }

      ByteUtil.putContent(certFile, crtBytes);
      ByteUtil.putContent(caFile, crtBytes);
      ByteUtil.putContent(keyFile, pvtKeyBytes);

      final Process zmCertMgrProcess = processStarter.start(CERT_MGR, VERIFY_CERT_COMMAND,
          CERT_TYPE_COMM,
          keyFile, certFile, caFile);
      verifyResult = this.verifyCrtCommandResult(
          new String(zmCertMgrProcess.getInputStream().readAllBytes()));
      ZimbraLog.security.info(" GetVerifyCertResponse:" + verifyResult);

      File comm_priv = new File(keyFile);
      if (!comm_priv.delete()) {
        throw new SecurityException("Deleting commercial private key file failed.");
      }
      File comm_cert = new File(certFile);
      if (!comm_cert.delete()) {
        throw new SecurityException("Deleting commercial certificate file failed.");
      }
      File comm_ca = new File(caFile);
      if (!comm_ca.delete()) {
        throw new SecurityException("Deleting commercial CA certificate file failed.");
      }

      if (!comm_path.delete()) {
        throw new SecurityException("Deleting directory of certificate/key failed.");
      }

    } catch (SecurityException se) {
      ZimbraLog.security.error("File(s) of commercial certificates/prvkey was not deleted", se);
    } catch (IOException ioe) {
      throw ServiceException.FAILURE("IOException occurred while running cert verification command",
          ioe);
    }

    response.addAttribute(CertMgrConstants.A_verifyResult, verifyResult);
    return response;
  }

  /**
   * Replaces spaces with new lines.
   *
   * @param input input string
   * @return formatted string
   */
  private String formatWithNewLine(String input) {
    return input.replaceAll("\\s", "\n");
  }

  /**
   * Parses the command output and checks if it was successful based on displayed information.
   *
   * @param commandResult the received command result
   * @return if successful
   */
  private boolean verifyCrtCommandResult(String commandResult) {
    return !StringUtils.containsIgnoreCase(commandResult, "error");
  }

}


