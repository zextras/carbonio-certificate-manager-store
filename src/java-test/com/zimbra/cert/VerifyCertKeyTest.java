package com.zimbra.cert;

import static com.zimbra.common.soap.CertMgrConstants.A_verifyResult;
import static com.zimbra.common.soap.CertMgrConstants.VERIFY_CERTKEY_REQUEST;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import com.zimbra.cert.util.ProcessStarter;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.CertMgrConstants;
import com.zimbra.common.soap.Element;
import com.zimbra.common.soap.Element.XMLElement;
import com.zimbra.common.soap.SoapProtocol;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.service.AuthProvider;
import com.zimbra.soap.JaxbUtil;
import com.zimbra.soap.SoapEngine;
import com.zimbra.soap.ZimbraSoapContext;
import com.zimbra.soap.admin.message.VerifyCertKeyRequest;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mock;
import org.mockito.Mockito;

public class VerifyCertKeyTest {

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @Rule
  public ExpectedException exceptionRule = ExpectedException.none();

  @Test(expected = ServiceException.class)
  public void shouldReturnInvalidIfPvtKeyEmpty() throws Exception {
    final VerifyCertKey verifyCertKey = new VerifyCertKey(
        mock(ProcessStarter.class), testFolder.getRoot().getAbsolutePath());
    final Process processMock = mock(Process.class);
    // prepare request
    Map<String, Object> context = new HashMap<String, Object>();
    ZimbraSoapContext zsc =
        new ZimbraSoapContext(
            mock(AuthToken.class),
            "1",
            SoapProtocol.Soap12,
            SoapProtocol.Soap12);
    context.put(SoapEngine.ZIMBRA_CONTEXT, zsc);
    final XMLElement request = new XMLElement(VERIFY_CERTKEY_REQUEST);
    request.addUniqueElement("cert").addText("test");
    request.addUniqueElement("privKey").addText("");
    verifyCertKey.handle(request, context);
  }

  @Test
  public void shouldReturnTrueIfNoErrorInProcess() throws Exception {
    final ProcessStarter processStarter = mock(ProcessStarter.class);
    final VerifyCertKey verifyCertKey = new VerifyCertKey(processStarter, testFolder.getRoot().getAbsolutePath());
    final Process processMock = mock(Process.class);
    when(processStarter.start(any())).thenReturn(processMock);
    when(processMock.waitFor()).thenReturn(1);
    final ByteArrayInputStream mockProcessResult = new ByteArrayInputStream(
        "The process went smooth".getBytes(StandardCharsets.UTF_8));
    when(processMock.getInputStream()).thenReturn(mockProcessResult);
    // prepare request
    Map<String, Object> context = new HashMap<String, Object>();
    ZimbraSoapContext zsc =
        new ZimbraSoapContext(
            mock(AuthToken.class),
            "1",
            SoapProtocol.Soap12,
            SoapProtocol.Soap12);
    context.put(SoapEngine.ZIMBRA_CONTEXT, zsc);
    final XMLElement request = new XMLElement(VERIFY_CERTKEY_REQUEST);
    request.addAttribute(CertMgrConstants.E_cert,"test");
    request.addAttribute(CertMgrConstants.A_privkey, "test2");
    final Element result = verifyCertKey.handle(request, context);
    assertEquals("1", result.getAttribute(A_verifyResult));
  }

  @Test
  public void shouldReturnFalseIfErrorInProcess() throws Exception {
    final ProcessStarter processStarter = mock(ProcessStarter.class);
    final VerifyCertKey verifyCertKey = new VerifyCertKey(processStarter, testFolder.getRoot().getAbsolutePath());
    final Process processMock = mock(Process.class);
    when(processStarter.start(any())).thenReturn(processMock);
    when(processMock.waitFor()).thenReturn(1);
    final ByteArrayInputStream mockProcessResult = new ByteArrayInputStream(
        "Error: The process did not go very smooth".getBytes(StandardCharsets.UTF_8));
    when(processMock.getInputStream()).thenReturn(mockProcessResult);
    // prepare request
    Map<String, Object> context = new HashMap<String, Object>();
    ZimbraSoapContext zsc =
        new ZimbraSoapContext(
            mock(AuthToken.class),
            "1",
            SoapProtocol.Soap12,
            SoapProtocol.Soap12);
    context.put(SoapEngine.ZIMBRA_CONTEXT, zsc);
    final XMLElement request = new XMLElement(VERIFY_CERTKEY_REQUEST);
    request.addAttribute(CertMgrConstants.E_cert,"test");
    request.addAttribute(CertMgrConstants.A_privkey, "test2");
    final Element result = verifyCertKey.handle(request, context);
    assertEquals("0", result.getAttribute(A_verifyResult));
  }

}
