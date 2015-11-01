package com.daedafusion.aniketos.exceptions;

import org.apache.log4j.Logger;

import javax.ws.rs.WebApplicationException;

/**
 * Created by mphilpot on 7/18/14.
 */
public class PasswordResetRequiredException extends WebApplicationException
{
    private static final Logger log = Logger.getLogger(PasswordResetRequiredException.class);

    public PasswordResetRequiredException()
    {
        super(419);
    }

    public PasswordResetRequiredException(String message)
    {
        super(message, 419);
    }
}
