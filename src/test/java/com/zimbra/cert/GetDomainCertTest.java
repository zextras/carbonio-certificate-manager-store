package com.zimbra.cert;

import static com.zimbra.common.soap.AdminConstants.A_DOMAIN;
import static com.zimbra.common.soap.CertMgrConstants.GET_DOMAIN_CERT_REQUEST;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.zimbra.common.account.Key.DomainBy;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.Element;
import com.zimbra.common.soap.Element.XMLElement;
import com.zimbra.common.soap.SoapProtocol;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.soap.SoapEngine;
import com.zimbra.soap.ZimbraSoapContext;
import java.util.HashMap;
import java.util.Map;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class GetDomainCertTest {
  private final String domainId = "domainId";
  private final Map<String, Object> context = new HashMap<>();
  Provisioning provisioning = mock(Provisioning.class);

  @Rule public ExpectedException expectedEx = ExpectedException.none();

  @Before
  public void setUp() throws Exception {
    final ZimbraSoapContext zsc =
        new ZimbraSoapContext(mock(AuthToken.class), "1", SoapProtocol.Soap12, SoapProtocol.Soap12);
    context.put(SoapEngine.ZIMBRA_CONTEXT, zsc);
    Provisioning.setInstance(provisioning);
  }

  @Test(expected = ServiceException.class)
  public void shouldReturnInvalidIfNoSuchDomain() throws Exception {
    when(provisioning.get(DomainBy.id, domainId)).thenReturn(null);

    final GetDomainCert getDomainCert = new GetDomainCert();
    final XMLElement request = new XMLElement(GET_DOMAIN_CERT_REQUEST);
    request.addNonUniqueElement(A_DOMAIN).addText(domainId);
    getDomainCert.handle(request, context);
  }

  @Test(expected = ServiceException.class)
  public void shouldReturnInvalidIfNoDomainCert() throws Exception {
    final Domain domain = mock(Domain.class);
    when(provisioning.get(DomainBy.id, domainId)).thenReturn(domain);
    when(domain.getSSLCertificate()).thenReturn(null);

    final GetDomainCert getDomainCert = new GetDomainCert();
    final XMLElement request = new XMLElement(GET_DOMAIN_CERT_REQUEST);
    request.addNonUniqueElement(A_DOMAIN).addText(domainId);
    getDomainCert.handle(request, context);
  }

  @Test(expected = ServiceException.class)
  public void shouldThrowExceptionWithInvalidCertData() throws Exception {
    final Domain domain = mock(Domain.class);
    when(provisioning.get(DomainBy.id, domainId)).thenReturn(domain);
    when(domain.getDomainName()).thenReturn("domainName");
    when(domain.getSSLCertificate())
        .thenReturn(
            "-----BEGIN CERTIFICATE-----\n"
            + "MIIFPjCCBCagAwIBAgISAyeF5ryS59TmpV5xTYquviaNMA0GCSqGSIb3DQEBCwUA\n"
            + "-----END CERTIFICATE-----\n");

    final GetDomainCert getDomainCert = new DumbGetDomainCertHandler();
    final XMLElement request = new XMLElement(GET_DOMAIN_CERT_REQUEST);
    request.addNonUniqueElement(A_DOMAIN).addText(domainId);
    getDomainCert.handle(request, context);
  }

  @Test
  public void shouldReturnSuccessForDomainWithValidCert() throws Exception {
    final Domain domain = mock(Domain.class);
    when(provisioning.get(DomainBy.id, domainId)).thenReturn(domain);
    when(domain.getDomainName()).thenReturn("domainName");
    when(domain.getSSLCertificate())
        .thenReturn(
                "-----BEGIN CERTIFICATE-----\n"
                + "MIIFPjCCBCagAwIBAgISAyeF5ryS59TmpV5xTYquviaNMA0GCSqGSIb3DQEBCwUA\n"
                + "MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\n"
                + "EwJSMzAeFw0yMjExMjIxNjI2MDFaFw0yMzAyMjAxNjI2MDBaMCcxJTAjBgNVBAMT\n"
                + "HHdlYm1haWwtYWNtZS5kZW1vLnpleHRyYXMuaW8wggEiMA0GCSqGSIb3DQEBAQUA\n"
                + "A4IBDwAwggEKAoIBAQDdo/18KgJWki8yGVKC+cSV1wUJ9RKuOzLS7FdHd0RIt0H6\n"
                + "lT9UriqWd2Yoc49wGJnvs2JY9K8oS3qj1VCAMMUrLBPt6NXPrPAU9uCG7p4e1R8o\n"
                + "jgJq1Wumhxaua+btaPnkEJefGge0zuNDP0aEusK+zH9mCxgMqTDcbkjqaI6FFxFb\n"
                + "++HTMe/c4quAput2FzpmUY5loLsomcd4eq28pWP4zRSli31HxEBFNgk6V6zVKAGl\n"
                + "d92jrYNXNzNVQE3zAa5Ds9VyJq4Z6/8/Irl9lG7GKeF9c4TIBzPUvoHQOcbyC3LU\n"
                + "1mlJtbkHiouGwFkSgJGH0NPmZzj8eA5VNhEjm+GVAgMBAAGjggJXMIICUzAOBgNV\n"
                + "HQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1Ud\n"
                + "EwEB/wQCMAAwHQYDVR0OBBYEFGHHL5z1LwZqLDE1YHc76YWctfCuMB8GA1UdIwQY\n"
                + "MBaAFBQusxe3WFbLrlAJQOYfr52LFMLGMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEF\n"
                + "BQcwAYYVaHR0cDovL3IzLm8ubGVuY3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8v\n"
                + "cjMuaS5sZW5jci5vcmcvMCcGA1UdEQQgMB6CHHdlYm1haWwtYWNtZS5kZW1vLnpl\n"
                + "eHRyYXMuaW8wTAYDVR0gBEUwQzAIBgZngQwBAgEwNwYLKwYBBAGC3xMBAQEwKDAm\n"
                + "BggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlwdC5vcmcwggEEBgorBgEE\n"
                + "AdZ5AgQCBIH1BIHyAPAAdwB6MoxU2LcttiDqOOBSHumEFnAyE4VNO9IrwTpXo1Lr\n"
                + "UgAAAYSgYBDwAAAEAwBIMEYCIQDCZVS/DDy0C2R9IrY1ScTonqeedlI7ZjXo7R5R\n"
                + "ZunbhwIhAMwCpmEsi0NUx1PhhNUwP3x85bRUEq4S+w/0/Nwj1I0tAHUAtz77JN+c\n"
                + "Tbp18jnFulj0bF38Qs96nzXEnh0JgSXttJkAAAGEoGAS9AAABAMARjBEAiAbZ6Ag\n"
                + "fsdche4bRXR6G/CAfNk6sRyA5W3ThLWyn9+vfAIgdYMflSb3bZyQbuhKB4zt3s1O\n"
                + "BXrSDRXXrPYnF5rMWhEwDQYJKoZIhvcNAQELBQADggEBAJXIkzjX3thAZyBSj9lr\n"
                + "It8ipidZNghgI27d7cqntkdsIDWQYyRRbS05GObMoAEiQnFti8EGnqQqEFkgOAj1\n"
                + "9wXjSQdOGJjzm+giMhci2VMBC4N/7fWOSxWQ+jmVsYOLUFFb8VBuhWpwU5VHOAcv\n"
                + "6cHuQKNOw8cYm9BFtdKqeexcTkflpWVsNK/CxIiK3cf9/p43MLO73AdGPT2g6DEk\n"
                + "f+6Ay6pRLopibLZgGWqqBxevG9Pag5VN1CXcR5cu431Ic5l6NLJp58ED9qw8rf/7\n"
                + "2gAhU3H9TC8UfXXnezzd5PSRjFAi05ciYyUQv+jtAN/U/wGDpiZ1QySvq0p6NC0J\n"
                + "f+g=\n"
                + "-----END CERTIFICATE-----\n");

    final GetDomainCert getDomainCert = new DumbGetDomainCertHandler();
    final XMLElement request = new XMLElement(GET_DOMAIN_CERT_REQUEST);
    request.addNonUniqueElement(A_DOMAIN).addText(domainId);
    final Element response = getDomainCert.handle(request, context);
    assertEquals(
        "<GetDomainCertResponse"
            + " xmlns=\"urn:zimbraAdmin\">"
            + "<cert domain=\"domainName\">"
            + "<subject>CN=webmail-acme.demo.zextras.io</subject>"
            + "<SubjectAltName>webmail-acme.demo.zextras.io</SubjectAltName>"
            + "<issuer>CN=R3,O=Let's Encrypt,C=US</issuer>"
            + "<notBefore>Nov 22 2022 17:26:01 CET</notBefore>"
            + "<notAfter>Feb 20 2023 17:26:00 CET</notAfter>"
            + "</cert>"
            + "</GetDomainCertResponse>",
        response.toString());
  }
}
