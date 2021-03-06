package com.daedafusion.aniketos.exceptions;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/24/14.
 */
public class ServiceErrorException extends Exception
{
    private static final Logger log = Logger.getLogger(ServiceErrorException.class);

    public ServiceErrorException(String message)
    {
        super(message);
    }

    public ServiceErrorException(String message, Throwable e)
    {
        super(message, e);
    }
}
