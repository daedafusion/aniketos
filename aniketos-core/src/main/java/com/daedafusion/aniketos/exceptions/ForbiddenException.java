package com.daedafusion.aniketos.exceptions;

import org.apache.log4j.Logger;

import javax.ws.rs.WebApplicationException;

/**
 * Created by mphilpot on 7/18/14.
 */
public class ForbiddenException extends WebApplicationException
{
    private static final Logger log = Logger.getLogger(ForbiddenException.class);

    public ForbiddenException()
    {
        super(403);
    }

    public ForbiddenException(String message)
    {
        super(message, 403);
    }
}
