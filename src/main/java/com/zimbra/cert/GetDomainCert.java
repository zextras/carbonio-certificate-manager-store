package com.zimbra.cert;

import com.zimbra.common.account.Key.DomainBy;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.AdminConstants;
import com.zimbra.common.soap.CertMgrConstants;
import com.zimbra.common.soap.Element;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.accesscontrol.AdminRight;
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


public class GetDomainCert extends AdminDocumentHandler {

  private static final String CERT_TYPE = "X.509";
  private static final String DATE_PATTERN = "MMM dd yyyy HH:mm:ss z";

  @Override

  public Element handle(Element request, Map<String, Object> context) throws ServiceException {

    ZimbraSoapContext lc = getZimbraSoapContext(context);

    Provisioning prov = Provisioning.getInstance();
    String domainName = request.getAttribute(AdminConstants.A_DOMAIN);
    Domain domain = prov.get(DomainBy.name, domainName);

    if (domain == null) {
      throw ServiceException.INVALID_REQUEST(
          "Domain with name " + domainName + " could not be found", null);
    }

    checkDomainRight(lc, domain, AdminRight.PR_ALWAYS_ALLOW);

    Element response = lc.createElement(CertMgrConstants.GET_DOMAIN_CERT_RESPONSE);
    Element certElement = response
        .addNonUniqueElement(CertMgrConstants.E_cert)
        .addAttribute(AdminConstants.A_DOMAIN, domainName);

    try (InputStream inStream = new ByteArrayInputStream(domain.getSSLCertificate().getBytes())) {
      CertificateFactory cf = CertificateFactory.getInstance(CERT_TYPE);
      X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);

      addCertInfo(certElement, cert);
    } catch (IOException | CertificateException e) {
      throw ServiceException.FAILURE("Failure on parsing domain certificate: " + e.getMessage());
    }

    return response;
  }

  private void addCertInfo(Element certElement, X509Certificate cert)
      throws CertificateParsingException {
    addChildElement(certElement, CertMgrConstants.E_SUBJECT, cert.getSubjectX500Principal().getName());
    addChildElement(certElement, CertMgrConstants.E_SUBJECT_ALT_NAME, cert.getSubjectAlternativeNames().toString());
    addChildElement(certElement, CertMgrConstants.E_ISSUER, cert.getIssuerX500Principal().getName());
    addChildElement(certElement, CertMgrConstants.E_NOT_BEFORE, formatDate(cert.getNotBefore()));
    addChildElement(certElement, CertMgrConstants.E_NOT_AFTER, formatDate(cert.getNotAfter()));
  }

  private void addChildElement(Element parentElement, String name, String value) {
    Element childElement = parentElement.addNonUniqueElement(name);
    childElement.setText(value);
  }

  private String formatDate(Date date) {
    DateFormat dateFormat = new SimpleDateFormat(DATE_PATTERN);
    return dateFormat.format(date);
  }
}
