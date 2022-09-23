package com.zimbra.cert;

import static com.zimbra.common.soap.CertMgrConstants.A_verifyResult;
import static com.zimbra.common.soap.CertMgrConstants.VERIFY_CERTKEY_REQUEST;
import static org.junit.Assert.*;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.zimbra.cert.util.ProcessStarter;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.CertMgrConstants;
import com.zimbra.common.soap.Element;
import com.zimbra.common.soap.Element.XMLElement;
import com.zimbra.common.soap.SoapProtocol;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.soap.SoapEngine;
import com.zimbra.soap.ZimbraSoapContext;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

public class VerifyCertKeyTest {

  @Rule public TemporaryFolder testFolder = new TemporaryFolder();

  @Rule public ExpectedException exceptionRule = ExpectedException.none();

  private String getBaseOperationPath() {
    return testFolder.getRoot().getAbsolutePath()
        + File.separator
        + UUID.randomUUID()
        + File.separator;
  }

  @Test(expected = ServiceException.class)
  public void shouldReturnInvalidIfPvtKeyEmpty() throws Exception {
    final VerifyCertKey verifyCertKey =
        new VerifyCertKey(mock(ProcessStarter.class), this::getBaseOperationPath);
    // prepare request
    Map<String, Object> context = new HashMap<String, Object>();
    ZimbraSoapContext zsc =
        new ZimbraSoapContext(mock(AuthToken.class), "1", SoapProtocol.Soap12, SoapProtocol.Soap12);
    context.put(SoapEngine.ZIMBRA_CONTEXT, zsc);
    final XMLElement request = new XMLElement(VERIFY_CERTKEY_REQUEST);
    request.addUniqueElement("cert").addText("test");
    request.addUniqueElement("privKey").addText("");
    verifyCertKey.handle(request, context);
  }

  @Test
  public void shouldReturnTrueIfNoErrorInProcess() throws Exception {
    final ProcessStarter processStarter = mock(ProcessStarter.class);
    final VerifyCertKey verifyCertKey =
        new VerifyCertKey(processStarter, this::getBaseOperationPath);
    final Process processMock = mock(Process.class);
    when(processStarter.start(any())).thenReturn(processMock);
    when(processMock.waitFor()).thenReturn(1);
    final ByteArrayInputStream mockProcessResult =
        new ByteArrayInputStream("The process went smooth".getBytes(StandardCharsets.UTF_8));
    when(processMock.getInputStream()).thenReturn(mockProcessResult);
    // prepare request
    Map<String, Object> context = new HashMap<String, Object>();
    ZimbraSoapContext zsc =
        new ZimbraSoapContext(mock(AuthToken.class), "1", SoapProtocol.Soap12, SoapProtocol.Soap12);
    context.put(SoapEngine.ZIMBRA_CONTEXT, zsc);
    final XMLElement request = new XMLElement(VERIFY_CERTKEY_REQUEST);
    request.addAttribute(CertMgrConstants.E_cert, "test");
    request.addAttribute(CertMgrConstants.A_privkey, "test2");
    final Element result = verifyCertKey.handle(request, context);
    assertEquals("1", result.getAttribute(A_verifyResult));
  }

  @Test
  public void shouldReturnFalseIfErrorInProcess() throws Exception {
    final ProcessStarter processStarter = mock(ProcessStarter.class);
    final VerifyCertKey verifyCertKey =
        new VerifyCertKey(processStarter, this::getBaseOperationPath);
    final Process processMock = mock(Process.class);
    when(processStarter.start(any())).thenReturn(processMock);
    when(processMock.waitFor()).thenReturn(1);
    final ByteArrayInputStream mockProcessResult =
        new ByteArrayInputStream(
            "Error: The process did not go very smooth".getBytes(StandardCharsets.UTF_8));
    when(processMock.getInputStream()).thenReturn(mockProcessResult);
    // prepare request
    Map<String, Object> context = new HashMap<String, Object>();
    ZimbraSoapContext zsc =
        new ZimbraSoapContext(mock(AuthToken.class), "1", SoapProtocol.Soap12, SoapProtocol.Soap12);
    context.put(SoapEngine.ZIMBRA_CONTEXT, zsc);
    final XMLElement request = new XMLElement(VERIFY_CERTKEY_REQUEST);
    request.addAttribute(CertMgrConstants.E_cert, "test");
    request.addAttribute(CertMgrConstants.A_privkey, "test2");
    final Element result = verifyCertKey.handle(request, context);
    assertEquals("0", result.getAttribute(A_verifyResult));
  }

  /**
   * When copy/pasting private key or crt files, instead of new lines we receive spaces. This tests
   * verifies that the returned value is as expected for such inputs.
   */
  @Test
  public void shouldMatchExpectedFormatWhenCertificateInputIsValid() {
    final ProcessStarter processStarter = mock(ProcessStarter.class);
    final VerifyCertKey verifyCertKey =
        new VerifyCertKey(processStarter, this::getBaseOperationPath);
    final String testContent =
        "-----BEGIN CERTIFICATE----- this is my cert "
            + "-----END CERTIFICATE----- "
            + "-----BEGIN CERTIFICATE----- another -----END CERTIFICATE-----";
    final String expectedContent =
        "-----BEGIN CERTIFICATE-----"
            + System.lineSeparator()
            + "this"
            + System.lineSeparator()
            + "is"
            + System.lineSeparator()
            + "my"
            + System.lineSeparator()
            + "cert"
            + System.lineSeparator()
            + "-----END CERTIFICATE-----"
            + System.lineSeparator()
            + "-----BEGIN CERTIFICATE-----"
            + System.lineSeparator()
            + "another"
            + System.lineSeparator()
            + "-----END CERTIFICATE-----"
            + System.lineSeparator();
    assertEquals(expectedContent, verifyCertKey.formatValidContent(testContent));
    // transforming the already expected content should have no effect
    assertEquals(expectedContent, verifyCertKey.formatValidContent(expectedContent));
  }

  /**
   * If the input has more than one space in between headers or content, the result should be
   * different from a proper well-formatted certificate file.
   */
  @Test
  public void shouldNotMatchExpectedContentWhenInputMalformed() {
    final ProcessStarter processStarter = mock(ProcessStarter.class);
    final VerifyCertKey verifyCertKey =
        new VerifyCertKey(processStarter, this::getBaseOperationPath);
    // Malformed means more than one space
    final String content =
        "-----BEGIN CERTIFICATE----- this    is my cert -----END CERTIFICATE----- "
            + "-----BEGIN CERTIFICATE----- another -----END CERTIFICATE-----";
    final String expectedContent =
        "-----BEGIN CERTIFICATE-----"
            + System.lineSeparator()
            + "this"
            + System.lineSeparator()
            + "is"
            + System.lineSeparator()
            + "my"
            + System.lineSeparator()
            + "cert"
            + System.lineSeparator()
            + "-----END CERTIFICATE-----"
            + System.lineSeparator()
            + "-----BEGIN CERTIFICATE-----"
            + System.lineSeparator()
            + "another"
            + System.lineSeparator()
            + "-----END CERTIFICATE-----"
            + System.lineSeparator();
    assertFalse(Objects.equals(expectedContent, verifyCertKey.formatValidContent(content)));
  }
}
