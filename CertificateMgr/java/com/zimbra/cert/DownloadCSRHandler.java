package com.zimbra.cert;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpState;
import org.apache.commons.httpclient.methods.GetMethod;

import com.zimbra.common.httpclient.HttpClientUtil;
import com.zimbra.common.localconfig.LC;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.AdminConstants;
import com.zimbra.common.util.ByteUtil;
import com.zimbra.common.util.ZimbraHttpConnectionManager;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.Server;
import com.zimbra.cs.account.accesscontrol.Rights.Admin;
import com.zimbra.cs.extension.ExtensionHttpHandler;
import com.zimbra.cs.servlet.ZimbraServlet;

public class DownloadCSRHandler extends ExtensionHttpHandler {
    public static final String HANDLER_PATH_NAME = "downloadcsr";
    public static final String CSR_FILE_NAME = LC.zimbra_home.value() + "/ssl/zimbra/commercial/commercial.csr"; // this path is hardcoded in /opt/zimbra/bin/zmcertmgr
    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        AuthToken authToken = ZimbraServlet.getAdminAuthTokenFromCookie(req, resp);
        if (authToken == null) {
            ZimbraLog.extensions.error("Missing authtoken");
            resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        String serverId = req.getParameter(AdminConstants.A_SERVER);
        Provisioning prov = Provisioning.getInstance();
        try {
            Server server;
            if (serverId == null) {
                server = prov.getLocalServer();
            } else {
                server = prov.getServerById(serverId);
            }
            if (server == null) {
                ZimbraLog.extensions.error("Cannot find server with ID %s", serverId);
                resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                return;
            }
            try {
                checkRight(authToken, server, Admin.R_getCSR);
                if (server.isLocalServer()) {
                    // send CSR file
                    getCSRFile(resp.getOutputStream(), resp);
                } else {
                    // forward request to target server
                    proxyRequestWithAuth(authToken, server, resp);
                }
            } catch (ServiceException e) {
                ZimbraLog.extensions.error("Admin user %s does not have permission %s to download CSR from server %s",
                        authToken.getAccount().getName(), Admin.R_getCSR.toString(), serverId);
                resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }
        } catch (ServiceException e) {
            resp.setHeader(ZimbraServlet.ZIMBRA_FAULT_CODE_HEADER, e.getCode());
            resp.setHeader(ZimbraServlet.ZIMBRA_FAULT_MESSAGE_HEADER, e.getMessage());
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    private static void getCSRFile(OutputStream out, HttpServletResponse resp) throws FileNotFoundException,
            IOException {
        resp.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        resp.setHeader("Pragma", "no-cache");
        resp.setHeader("Expires", "0");
        resp.setContentType("application/x-download");
        resp.setHeader("Content-Disposition", "attachment; filename=commercial.csr");
        InputStream in = null;
        try {
            in = new BufferedInputStream(new FileInputStream(CSR_FILE_NAME));
            byte[] buf = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(buf)) != -1) {
                out.write(buf, 0, bytesRead);
            }
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    private void proxyRequestWithAuth(AuthToken authToken, Server server, HttpServletResponse resp)
            throws ServiceException, HttpException, IOException {
        HttpClient client = ZimbraHttpConnectionManager.getInternalHttpConnMgr().getDefaultHttpClient();
        HttpState state = HttpClientUtil.newHttpState(authToken.toZAuthToken(), server.getServiceHostname(), true);
        GetMethod method = new GetMethod(String.format("https://%s:%s/service/extension/%s/%s",
                server.getServiceHostname(), server.getAdminPortAsString(), ZimbraCertMgrExt.EXTENSION_NAME_CERTMGR,
                HANDLER_PATH_NAME));
        client.setState(state);
        int status = client.executeMethod(method);
        InputStream responseBody = method.getResponseBodyAsStream();
        resp.setStatus(status);
        for (Header h : method.getResponseHeaders()) {
            resp.addHeader(h.getName(), h.getValue());
        }
        if (responseBody != null) {
            ByteUtil.copy(responseBody, true, resp.getOutputStream(), true);
        }
    }

    @Override
    public String getPath() {
        return super.getPath() + "/" + HANDLER_PATH_NAME;
    }
}