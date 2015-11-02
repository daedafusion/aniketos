package com.daedafusion.aniketos.framework.providers;

import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.identity.providers.IdentityStoreProvider;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by mphilpot on 8/20/14.
 */
public class StubIdentityStoreProvider extends AbstractProvider implements IdentityStoreProvider
{
    private static final Logger log = Logger.getLogger(StubIdentityStoreProvider.class);

    @Override
    public Identity getIdentity(Subject subject, String user, String domain)
    {
        return RandomUserMe.getIdentity(user, domain);
    }

    @Override
    public List<Identity> getIdentitiesForDomain(Subject subject, String domain)
    {
        // TODO make some deterministic list
        return new ArrayList<Identity>();
    }

    @Override
    public void setPassword(Subject subject, String user, String domain, String password)
    {
        // Empty
    }

    @Override
    public String getAuthority()
    {
        return StubIdentityStoreProvider.class.getName();
    }
}
