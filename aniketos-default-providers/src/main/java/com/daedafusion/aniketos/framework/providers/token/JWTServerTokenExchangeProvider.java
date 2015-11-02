package com.daedafusion.aniketos.framework.providers.token;

import com.daedafusion.aniketos.framework.providers.ServerTokenExchangeProvider;
import com.daedafusion.sf.AbstractProvider;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 1/22/15.
 */
public class JWTServerTokenExchangeProvider extends AbstractProvider implements ServerTokenExchangeProvider
{
    private static final Logger log = Logger.getLogger(JWTServerTokenExchangeProvider.class);

    @Override
    public boolean isTokenValidNoSession(String tokenString)
    {
        return JWTStore.getInstance().isValidToken(tokenString, false);
    }
}
