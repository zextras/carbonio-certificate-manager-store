package com.zimbra.cert;

import static com.zimbra.common.soap.AdminConstants.A_DOMAIN;
import static com.zimbra.common.soap.CertMgrConstants.GET_DOMAIN_CERT_REQUEST;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.zimbra.common.account.Key.DomainBy;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.Element.XMLElement;
import com.zimbra.common.soap.SoapProtocol;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.soap.SoapEngine;
import com.zimbra.soap.ZimbraSoapContext;
import java.util.HashMap;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;


public class GetDomainCertTest {

  @Rule public ExpectedException expectedEx = ExpectedException.none();

  @Test(expected = ServiceException.class)
  public void shouldReturnInvalidIfNoSuchDomain() throws Exception {
    final String domainId = "domainId";
    Map<String, Object> context = new HashMap<>();
    ZimbraSoapContext zsc =
        new ZimbraSoapContext(mock(AuthToken.class), "1", SoapProtocol.Soap12, SoapProtocol.Soap12);
    context.put(SoapEngine.ZIMBRA_CONTEXT, zsc);
    Provisioning provisioning = mock(Provisioning.class);
    Provisioning.setInstance(provisioning);
    when(provisioning.get(DomainBy.id, domainId)).thenReturn(null);

    GetDomainCert getDomainCert = new GetDomainCert();
    final XMLElement request = new XMLElement(GET_DOMAIN_CERT_REQUEST);
    request.addNonUniqueElement(A_DOMAIN).addText(domainId);
    getDomainCert.handle(request, context);
  }

}