package com.zimbra.cert;

import static org.mockito.Mockito.mock;

import com.zimbra.cs.account.Domain;
import com.zimbra.cs.service.admin.AdminAccessControl;
import com.zimbra.soap.ZimbraSoapContext;

/**
 * For test purposes. Skip checking global and delegated admin rights.
 */
public class DumbGetDomainCertHandler extends GetDomainCert {

  @Override
  protected AdminAccessControl checkDomainRight(ZimbraSoapContext zsc, Domain d, Object needed) {
    return mock(AdminAccessControl.class);
  }

}
