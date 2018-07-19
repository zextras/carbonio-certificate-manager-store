package com.zimbra.qa.unittest;

import java.io.File;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.zimbra.cert.DownloadCSRHandler;
import com.zimbra.cert.ZimbraCertMgrExt;
import com.zimbra.common.httpclient.HttpClientUtil;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.Element;
import com.zimbra.common.soap.SoapHttpTransport;
import com.zimbra.common.soap.SoapProtocol;
import com.zimbra.common.util.ByteUtil;
import com.zimbra.common.util.StringUtil;
import com.zimbra.common.util.ZimbraCookie;
import com.zimbra.common.util.ZimbraHttpConnectionManager;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.accesscontrol.AdminRight;
import com.zimbra.cs.account.accesscontrol.Rights.Admin;
import com.zimbra.cs.account.soap.SoapProvisioning;
import com.zimbra.cs.ldap.LdapConstants;
import com.zimbra.cs.service.AuthProvider;
import com.zimbra.soap.JaxbUtil;
import com.zimbra.soap.admin.type.CacheEntryType;

public class TestDownloadCSR extends TestCase {
    private final static String MY_DOMAIN = "mydomain.com";
    private final static String DELEGATED_ADMIN_NAME = "delegated-admin@" + MY_DOMAIN;
    private SoapProvisioning adminSoapProv = null;
    private boolean deleteTestCSR = false;
    private String csrContent = null;
    private String DUMMY_CSR = "This is a dummy CSR file for testing";
    private Account domainAdmin = null;

    @Test
    public void testDownloadLocalCSRSuperAdmin() throws Exception {
        AuthToken at = AuthProvider.getAdminAuthToken();
        HttpClientBuilder httpClientBuilder = ZimbraHttpConnectionManager.getInternalHttpConnMgr().newHttpClient();
        BasicCookieStore cookieStore = new BasicCookieStore();
        at.encode(cookieStore, true, Provisioning.getInstance().getLocalServer().getName());
        httpClientBuilder.setDefaultCookieStore(cookieStore);
        HttpGet get = new HttpGet(getDownloadURL());
        HttpResponse httpResponse = HttpClientUtil.executeMethod(httpClientBuilder.build(), get);
        assertEquals("The GET request should succeed. Getting status code " + httpResponse.getStatusLine().getStatusCode(), HttpStatus.SC_OK, httpResponse.getStatusLine().getStatusCode());
        String downloadedContent = new String(ByteUtil.getContent(httpResponse.getEntity().getContent(), -1));
        assertNotNull("downloaded empty content", downloadedContent);
        assertTrue("downloaded content is not the same as CSR file on disk", downloadedContent.equals(csrContent));
    }

    @Test
    public void testDownloadCSRNoPermission() throws Exception {
        List<AdminRight> insufficientRights = new ArrayList<AdminRight>();
        insufficientRights.add(Admin.R_listAccount);
        insufficientRights.add(Admin.R_listServer);
        insufficientRights.add(Admin.R_listDomain);
        insufficientRights.add(Admin.R_installCertificate);
        String authToken = getDelegatedAdminAuthToken(insufficientRights);
        HttpClientBuilder httpClientBuilder = ZimbraHttpConnectionManager.getInternalHttpConnMgr().newHttpClient();
        BasicCookieStore state = new BasicCookieStore();
        state.addCookie(new BasicClientCookie(ZimbraCookie.authTokenCookieName(true),authToken));
        httpClientBuilder.setDefaultCookieStore(state);
        HttpGet get = new HttpGet(getDownloadURL());
        HttpResponse httpResponse = HttpClientUtil.executeMethod(httpClientBuilder.build(), get);
        assertEquals("The GET request should succeed. Getting status code " + httpResponse.getStatusLine().getStatusCode(), HttpStatus.SC_UNAUTHORIZED, httpResponse.getStatusLine().getStatusCode());
    }

    @Test
    public void testDownloadCSRDelegatedAdmin() throws Exception {
        List<AdminRight> sufficientRights = new ArrayList<AdminRight>();
        sufficientRights.add(Admin.R_getCSR);
        String authToken = getDelegatedAdminAuthToken(sufficientRights);
        HttpClientBuilder httpClientBuilder = ZimbraHttpConnectionManager.getInternalHttpConnMgr().newHttpClient();
        BasicCookieStore state = new BasicCookieStore();
        state.addCookie(new BasicClientCookie(ZimbraCookie.authTokenCookieName(true),authToken));
        httpClientBuilder.setDefaultCookieStore(state);
        HttpGet get = new HttpGet(getDownloadURL());
        HttpResponse httpResponse = HttpClientUtil.executeMethod(httpClientBuilder.build(), get);
        assertEquals("The GET request should succeed. Getting status code " + httpResponse, HttpStatus.SC_OK,
                httpResponse);
        String downloadedContent = new String(ByteUtil.getContent(httpResponse.getEntity().getContent(), -1));
        assertNotNull("downloaded empty content", downloadedContent);
        assertTrue("downloaded content is not the same as CSR file on disk", downloadedContent.equals(csrContent));
    }

    String getDownloadURL() throws Exception {
        int port = 7071;
        try {
            port = Provisioning.getInstance().getLocalServer().getIntAttr(Provisioning.A_zimbraAdminPort, 0);
        } catch (ServiceException e) {
            ZimbraLog.test.error("Unable to get admin SOAP port", e);
        }
        String host = Provisioning.getInstance().getLocalServer().getName();
        String downloadURL = "https://" + host + ":" + port + "/service/extension/"
                + ZimbraCertMgrExt.EXTENSION_NAME_CERTMGR + "/" + DownloadCSRHandler.HANDLER_PATH_NAME;
        return downloadURL;
    }

    String getDelegatedAdminAuthToken(List<AdminRight> relatedRights) throws Exception {
        Map<String, Object> attrs = new HashMap<String, Object>();
        StringUtil.addToMultiMap(attrs, Provisioning.A_zimbraIsDelegatedAdminAccount, LdapConstants.LDAP_TRUE);
        domainAdmin = adminSoapProv.createAccount(DELEGATED_ADMIN_NAME, TestUtil.DEFAULT_PASSWORD, attrs);
        assertNotNull("failed to create domin admin account", domainAdmin);
        for (AdminRight r : relatedRights) {
            String target = null;
            com.zimbra.cs.account.accesscontrol.TargetType targetType = null;
            if (r.getTargetType() == com.zimbra.cs.account.accesscontrol.TargetType.domain) {
                targetType = com.zimbra.cs.account.accesscontrol.TargetType.domain;
                target = MY_DOMAIN;
            } else if (r.getTargetType() == com.zimbra.cs.account.accesscontrol.TargetType.account
                    || r.getTargetType() == com.zimbra.cs.account.accesscontrol.TargetType.calresource) {
                targetType = com.zimbra.cs.account.accesscontrol.TargetType.domain;
                target = MY_DOMAIN;
            } else if (r.getTargetType() == com.zimbra.cs.account.accesscontrol.TargetType.server) {
                targetType = com.zimbra.cs.account.accesscontrol.TargetType.server;
                target = Provisioning.getInstance().getLocalServer().getName();
            }
            TestUtil.grantRightToAdmin(adminSoapProv,
                    com.zimbra.soap.type.TargetType.fromString(targetType.toString()), target, DELEGATED_ADMIN_NAME,
                    r.getName());
        }
        adminSoapProv.flushCache(CacheEntryType.acl, null);

        SoapHttpTransport transport = new SoapHttpTransport(TestUtil.getAdminSoapUrl());
        com.zimbra.soap.admin.message.AuthRequest req = new com.zimbra.soap.admin.message.AuthRequest(
                DELEGATED_ADMIN_NAME, TestUtil.DEFAULT_PASSWORD);
        Element resp = transport.invoke(JaxbUtil.jaxbToElement(req, SoapProtocol.SoapJS.getFactory()));
        com.zimbra.soap.admin.message.AuthResponse authResp = JaxbUtil.elementToJaxb(resp);
        String authToken = authResp.getAuthToken();
        return authToken;
    }

    @Before
    public void setUp() throws Exception {
        cleanup();
        adminSoapProv = TestUtil.newSoapProvisioning();
        File csrFile = new File(DownloadCSRHandler.CSR_FILE_NAME);
        if (!csrFile.exists()) {
            // create a dummy file
            deleteTestCSR = true;
            if (!csrFile.createNewFile()) {
                fail("cannot create a dummy csr file");
            }
            ByteUtil.putContent(DownloadCSRHandler.CSR_FILE_NAME, DUMMY_CSR.getBytes());
            csrContent = DUMMY_CSR;
        } else {
            csrContent = new String(ByteUtil.getContent(csrFile));
        }
        TestJaxbProvisioning.ensureDomainExists(MY_DOMAIN);
    }

    @After
    public void tearDown() throws Exception {
        cleanup();
    }

    private void cleanup() throws Exception {
        if(deleteTestCSR) {
            Files.deleteIfExists(FileSystems.getDefault().getPath(DownloadCSRHandler.CSR_FILE_NAME));
        }
        if (domainAdmin != null) {
            domainAdmin.deleteAccount();
        }
        TestJaxbProvisioning.deleteDomainIfExists(MY_DOMAIN);
    }
}
