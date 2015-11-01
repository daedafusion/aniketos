package com.daedafusion.aniketos.exceptions;

import org.apache.log4j.Logger;

import javax.ws.rs.WebApplicationException;

/**
 * Created by mphilpot on 7/18/14.
 */
public class PasswordQualityException extends WebApplicationException
{
    private static final Logger log = Logger.getLogger(PasswordQualityException.class);

    public PasswordQualityException()
    {
        super(412);
    }

    public PasswordQualityException(String message)
    {
        super(message, 412);
    }
}
