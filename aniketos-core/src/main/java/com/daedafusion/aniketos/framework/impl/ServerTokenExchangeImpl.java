package com.daedafusion.aniketos.framework.impl;

import com.daedafusion.aniketos.framework.ServerTokenExchange;
import com.daedafusion.aniketos.framework.providers.ServerTokenExchangeProvider;
import com.daedafusion.sf.AbstractService;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/21/14.
 */
public class ServerTokenExchangeImpl extends AbstractService<ServerTokenExchangeProvider> implements ServerTokenExchange
{
    private static final Logger log = Logger.getLogger(ServerTokenExchangeImpl.class);

    @Override
    public Class getProviderInterface()
    {
        return ServerTokenExchangeProvider.class;
    }

    @Override
    public boolean isTokenValidNoSession(String tokenString)
    {
        return getSingleProvider().isTokenValidNoSession(tokenString);
    }
}
