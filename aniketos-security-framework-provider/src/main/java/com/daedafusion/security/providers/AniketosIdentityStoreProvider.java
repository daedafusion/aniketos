package com.daedafusion.security.providers;

import com.daedafusion.aniketos.AniketosClient;
import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authentication.Token;
import com.daedafusion.security.authentication.TokenExchange;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.identity.providers.IdentityStoreProvider;
import org.apache.log4j.Logger;

import java.util.List;

/**
 * Created by mphilpot on 10/6/14.
 */
public class AniketosIdentityStoreProvider extends AbstractProvider implements IdentityStoreProvider
{
    private static final Logger log = Logger.getLogger(AniketosIdentityStoreProvider.class);

    /**
     *
     * @param username
     * @param domain if null, then username must be fully qualified
     * @return
     */
    @Override
    public Identity getIdentity(Subject subject, String username, String domain)
    {
        AniketosClient client = null;
        try
        {
            client = AniketosClientPool.getInstance().getPool().borrowObject();

            TokenExchange exchange = getServiceRegistry().getService(TokenExchange.class);
            Token token = exchange.exchange(subject);

            client.setAuthToken(token.getTokenString());

            return client.getIdentity(username, domain);
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new RuntimeException(e); // TODO Make this an official exception
        }
        finally
        {
            try
            {
                AniketosClientPool.getInstance().getPool().returnObject(client);
            }
            catch (Exception e)
            {
                log.error("",e);
            }
        }
    }

    @Override
    public List<Identity> getIdentitiesForDomain(Subject subject, String domain)
    {
        AniketosClient client = null;
        try
        {
            client = AniketosClientPool.getInstance().getPool().borrowObject();

            TokenExchange exchange = getServiceRegistry().getService(TokenExchange.class);
            Token token = exchange.exchange(subject);

            client.setAuthToken(token.getTokenString());

            return client.getIdentitiesForDomain(domain);
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new RuntimeException(e); // TODO Make this an official exception
        }
        finally
        {
            try
            {
                AniketosClientPool.getInstance().getPool().returnObject(client);
            }
            catch (Exception e)
            {
                log.error("",e);
            }
        }
    }

    /**
     *
     * @param username
     * @param domain if null, then username must be fully qualified
     * @param password
     */
    @Override
    public void setPassword(Subject subject, String username, String domain, String password)
    {

    }

    @Override
    public String getAuthority()
    {
        return AniketosIdentityStoreProvider.class.getName();
    }
}
