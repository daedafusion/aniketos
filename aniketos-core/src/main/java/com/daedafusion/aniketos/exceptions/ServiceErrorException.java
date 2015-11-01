package com.daedafusion.aniketos.exceptions;

import org.apache.log4j.Logger;

import javax.ws.rs.WebApplicationException;

/**
 * Created by mphilpot on 7/18/14.
 */
public class ServiceErrorException extends WebApplicationException
{
    private static final Logger log = Logger.getLogger(ServiceErrorException.class);

    public ServiceErrorException()
    {
        super(500);
    }

    public ServiceErrorException(String message)
    {
        super(message, 500);
    }
}
