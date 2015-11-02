package com.daedafusion.aniketos.exceptions;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/24/14.
 */
public class InvalidTokenException extends Exception
{
    private static final Logger log = Logger.getLogger(InvalidTokenException.class);

    public InvalidTokenException(String message)
    {
        super(message);
    }

    public InvalidTokenException(String message, Throwable e)
    {
        super(message, e);
    }
}
