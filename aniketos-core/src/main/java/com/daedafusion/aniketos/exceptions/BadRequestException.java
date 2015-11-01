package com.daedafusion.aniketos.exceptions;

import org.apache.log4j.Logger;

import javax.ws.rs.WebApplicationException;

/**
 * Created by mphilpot on 7/18/14.
 */
public class BadRequestException extends WebApplicationException
{
    private static final Logger log = Logger.getLogger(BadRequestException.class);

    public BadRequestException()
    {
        super(400);
    }

    public BadRequestException(String message)
    {
        super(message, 400);
    }
}
