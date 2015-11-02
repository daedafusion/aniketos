package com.daedafusion.aniketos.framework.providers.token;

import com.daedafusion.security.authentication.Token;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/21/14.
 */
public class JWToken implements Token
{
    private static final Logger log = Logger.getLogger(JWToken.class);
    private final String authority;
    private final String token;

    protected JWToken(String authority, String token)
    {
        this.authority = authority;
        this.token = token;
    }

    @Override
    public String getAuthority()
    {
        return authority;
    }

    @Override
    public String getTokenString()
    {
        return token;
    }
}
