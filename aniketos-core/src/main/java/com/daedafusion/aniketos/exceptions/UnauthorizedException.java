package com.daedafusion.aniketos.exceptions;

import org.apache.log4j.Logger;

import javax.ws.rs.WebApplicationException;

/**
 * Created by mphilpot on 7/18/14.
 */
public class UnauthorizedException extends WebApplicationException
{
    private static final Logger log = Logger.getLogger(UnauthorizedException.class);

    public UnauthorizedException()
    {
        super(401);
    }

    public UnauthorizedException(String message)
    {
        super(message, 401);
    }
}
