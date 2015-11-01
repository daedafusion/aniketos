package com.daedafusion.aniketos.framework;

/**
 * Created by mphilpot on 1/22/15.
 */
public interface ServerTokenExchange
{
    boolean isTokenValidNoSession(String tokenString);
}
