package com.daedafusion.aniketos.exceptions;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/24/14.
 */
public class AccountLockedException extends Exception
{
    private static final Logger log = Logger.getLogger(AccountLockedException.class);

    public AccountLockedException(String message)
    {
        super(message);
    }

    public AccountLockedException(String message, Throwable e)
    {
        super(message, e);
    }
}
