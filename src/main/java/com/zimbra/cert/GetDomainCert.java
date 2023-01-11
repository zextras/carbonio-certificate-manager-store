package com.zimbra.cert;

import com.zimbra.common.account.Key.DomainBy;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.AdminConstants;
import com.zimbra.common.soap.CertMgrConstants;
import com.zimbra.common.soap.Element;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.accesscontrol.Rights.Admin;
import com.zimbra.cs.service.admin.AdminDocumentHandler;
import com.zimbra.soap.ZimbraSoapContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Admin Handler class to get information about a domain certificate. It provides a way to access
 * all needed attributes of X.509 certificate using a standard java.security.cert package.
 */
public class GetDomainCert extends AdminDocumentHandler {

  private static final String CERT_TYPE = "X.509";
  private static final String DATE_PATTERN = "MMM dd yyyy HH:mm:ss z";

  /**
   * Handles the request. Searches a domain by name, checks admin rights (accessible to global and
   * delegated admin of requested domain), decrypts X.509 certificate, creates response element.
   *
   * @param request {@link Element} representation of {@link
   *     com.zimbra.soap.admin.message.GetDomainCertRequest}
   * @param context request context
   * @return {@link Element} representation of {@link
   *     com.zimbra.soap.admin.message.GetDomainCertResponse}
   * @throws ServiceException in case if a requested domain could not be found or if an error occurs
   *     during certificate parsing.
   */
  @Override
  public Element handle(Element request, Map<String, Object> context) throws ServiceException {

    ZimbraSoapContext zsc = getZimbraSoapContext(context);

    Provisioning prov = Provisioning.getInstance();
    String domainName = request.getAttribute(AdminConstants.A_DOMAIN);
    Domain domain = prov.get(DomainBy.name, domainName);

    if (domain == null) {
      throw ServiceException.INVALID_REQUEST(
          "Domain with name " + domainName + " could not be found.", null);
    }

    checkDomainRight(zsc, domain, Admin.R_getDomain);

    Element response = zsc.createElement(CertMgrConstants.GET_DOMAIN_CERT_RESPONSE);
    Element certElement =
        response
            .addNonUniqueElement(CertMgrConstants.E_cert)
            .addAttribute(AdminConstants.A_DOMAIN, domainName);

    try (InputStream inStream = new ByteArrayInputStream(domain.getSSLCertificate().getBytes())) {
      CertificateFactory cf = CertificateFactory.getInstance(CERT_TYPE);
      X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

      ZimbraLog.security.info("Parsing the cert info for domain: " + domainName);

      addCertInfo(certElement, cert);
    } catch (IOException | CertificateException e) {
      throw ServiceException.FAILURE("Failure on parsing domain certificate: " + e.getMessage());
    }

    return response;
  }

  private void addCertInfo(Element certElement, X509Certificate cert)
      throws CertificateParsingException {
    addChildElem(certElement, CertMgrConstants.E_SUBJECT, cert.getSubjectX500Principal().getName());
    addChildElem(certElement, CertMgrConstants.E_SUBJECT_ALT_NAME,
        cert.getSubjectAlternativeNames()
            .stream()
            .map(list -> list.get(1).toString())
            .collect(Collectors.joining(", ")));
    addChildElem(certElement, CertMgrConstants.E_ISSUER, cert.getIssuerX500Principal().getName());
    addChildElem(certElement, CertMgrConstants.E_NOT_BEFORE, formatDate(cert.getNotBefore()));
    addChildElem(certElement, CertMgrConstants.E_NOT_AFTER, formatDate(cert.getNotAfter()));
  }

  private void addChildElem(Element parentElement, String name, String value) {
    Element childElement = parentElement.addNonUniqueElement(name);
    childElement.setText(value);
  }

  private String formatDate(Date date) {
    DateFormat dateFormat = new SimpleDateFormat(DATE_PATTERN);
    return dateFormat.format(date);
  }
}
