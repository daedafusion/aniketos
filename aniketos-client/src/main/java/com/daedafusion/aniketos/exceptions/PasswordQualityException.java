package com.daedafusion.aniketos.exceptions;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/24/14.
 */
public class PasswordQualityException extends Exception
{
    private static final Logger log = Logger.getLogger(PasswordQualityException.class);

    public PasswordQualityException(String message)
    {
        super(message);
    }

    public PasswordQualityException(String message, Throwable e)
    {
        super(message, e);
    }
}
