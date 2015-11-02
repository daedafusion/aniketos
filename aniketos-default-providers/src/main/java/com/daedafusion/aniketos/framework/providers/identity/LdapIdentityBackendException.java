package com.daedafusion.aniketos.framework.providers.identity;

import org.apache.log4j.Logger;

/**
 * Created by patrick on 7/24/14.
 */
public class LdapIdentityBackendException extends Exception
{
    private static final Logger log = Logger.getLogger(LdapIdentityBackendException.class);

    public LdapIdentityBackendException(String message)
    {
        super(message);
    }

    public LdapIdentityBackendException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public LdapIdentityBackendException(Throwable cause)
    {
        super(cause);
    }
}
