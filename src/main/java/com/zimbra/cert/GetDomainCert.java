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
import java.util.Map;

public class GetDomainCert extends AdminDocumentHandler {

  @Override
  public Element handle(Element request, Map<String, Object> context) throws ServiceException{

    ZimbraSoapContext lc = getZimbraSoapContext(context);

    Provisioning prov = Provisioning.getInstance();
    String domainId = request.getAttribute(AdminConstants.A_DOMAIN);
    Domain domain = prov.get(DomainBy.id, domainId);

    if (domain == null) {
      throw ServiceException.INVALID_REQUEST("Domain with id " + domainId + " could not be found", null);
    }

    checkDomainRight(lc, domain, AdminRight.PR_ALWAYS_ALLOW);

    Element response = lc.createElement(CertMgrConstants.GET_DOMAIN_CERT_RESPONSE);
    addCertInfo(response, domain);

    return response;
  }

  public void addCertInfo(Element parent, Domain domain) {
      Element el = parent.addElement(CertMgrConstants.E_cert);
      el.addAttribute(AdminConstants.A_DOMAIN, domain.getName());
      el.addAttribute(AdminConstants.A_TYPE, domain.getSSLCertificate());
  }
}
