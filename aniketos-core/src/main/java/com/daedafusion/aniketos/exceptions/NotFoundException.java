package com.daedafusion.aniketos.exceptions;

import org.apache.log4j.Logger;

import javax.ws.rs.WebApplicationException;

/**
 * Created by mphilpot on 7/18/14.
 */
public class NotFoundException extends WebApplicationException
{
    private static final Logger log = Logger.getLogger(NotFoundException.class);

    public NotFoundException()
    {
        super(404);
    }

    public NotFoundException(String message)
    {
        super(message, 404);
    }
}
