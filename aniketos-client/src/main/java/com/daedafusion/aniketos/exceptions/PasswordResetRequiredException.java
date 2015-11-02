package com.daedafusion.aniketos.exceptions;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/24/14.
 */
public class PasswordResetRequiredException extends Exception
{
    private static final Logger log = Logger.getLogger(PasswordResetRequiredException.class);

    public PasswordResetRequiredException(String message)
    {
        super(message);
    }

    public PasswordResetRequiredException(String message, Throwable e)
    {
        super(message, e);
    }
}
