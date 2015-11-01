package com.daedafusion.aniketos.exceptions;

import org.apache.log4j.Logger;

import javax.ws.rs.WebApplicationException;

/**
 * Created by mphilpot on 7/18/14.
 */
public class IdentityLockedException extends WebApplicationException
{
    private static final Logger log = Logger.getLogger(IdentityLockedException.class);

    public IdentityLockedException()
    {
        super(423);
    }

    public IdentityLockedException(String message)
    {
        super(message, 423);
    }
}
