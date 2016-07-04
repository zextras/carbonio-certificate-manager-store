package com.zimbra.qa.unittest;

import java.io.File;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpState;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.cookie.CookiePolicy;
import org.apache.commons.httpclient.methods.GetMethod;
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
        HttpClient client = ZimbraHttpConnectionManager.getInternalHttpConnMgr().newHttpClient();
        HttpState state = new HttpState();
        at.encode(state, true, Provisioning.getInstance().getLocalServer().getName());
        client.setState(state);
        GetMethod get = new GetMethod(getDownloadURL());
        int statusCode = HttpClientUtil.executeMethod(client, get);
        assertEquals("The GET request should succeed. Getting status code " + statusCode, HttpStatus.SC_OK, statusCode);
        String downloadedContent = get.getResponseBodyAsString();
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
        HttpClient client = ZimbraHttpConnectionManager.getInternalHttpConnMgr().newHttpClient();
        HttpState state = new HttpState();
        state.addCookie(new org.apache.commons.httpclient.Cookie(Provisioning.getInstance().getLocalServer().getName(),
                ZimbraCookie.authTokenCookieName(true),
                authToken, "/", null, false));
        client.getParams().setCookiePolicy(CookiePolicy.BROWSER_COMPATIBILITY);
        client.setState(state);
        GetMethod get = new GetMethod(getDownloadURL());
        int statusCode = HttpClientUtil.executeMethod(client, get);
        assertEquals("The GET request should succeed. Getting status code " + statusCode, HttpStatus.SC_UNAUTHORIZED,
                statusCode);
    }

    @Test
    public void testDownloadCSRDelegatedAdmin() throws Exception {
        List<AdminRight> sufficientRights = new ArrayList<AdminRight>();
        sufficientRights.add(Admin.R_getCSR);
        String authToken = getDelegatedAdminAuthToken(sufficientRights);
        HttpClient client = ZimbraHttpConnectionManager.getInternalHttpConnMgr().newHttpClient();
        HttpState state = new HttpState();
        state.addCookie(new org.apache.commons.httpclient.Cookie(Provisioning.getInstance().getLocalServer().getName(),
                ZimbraCookie.authTokenCookieName(true),
                authToken, "/", null, false));
        client.getParams().setCookiePolicy(CookiePolicy.BROWSER_COMPATIBILITY);
        client.setState(state);
        GetMethod get = new GetMethod(getDownloadURL());
        int statusCode = HttpClientUtil.executeMethod(client, get);
        assertEquals("The GET request should succeed. Getting status code " + statusCode, HttpStatus.SC_OK,
                statusCode);
        String downloadedContent = get.getResponseBodyAsString();
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
