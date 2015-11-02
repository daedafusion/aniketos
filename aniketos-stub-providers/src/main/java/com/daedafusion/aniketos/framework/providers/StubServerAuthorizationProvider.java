package com.daedafusion.aniketos.framework.providers;

import com.daedafusion.sf.AbstractProvider;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 12/9/14.
 */
public class StubServerAuthorizationProvider extends AbstractProvider implements ServerAuthorizationProvider
{
    private static final Logger log = Logger.getLogger(StubServerAuthorizationProvider.class);

    @Override
    public String evaluate(String request)
    {
        // for now always return permit
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<Response xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\">\n" +
                "<Result>\n" +
                "<Decision>Permit</Decision>\n" +
                "<Status>\n" +
                "<StatusCode Value=\"urn:oasis:names:tc:xacml:1.0:status:ok\"/>\n" +
                "</Status>\n" +
                "</Result>\n" +
                "</Response>";
    }
}
