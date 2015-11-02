package com.daedafusion.aniketos;

import org.apache.http.client.utils.URIBuilder;
import org.apache.log4j.Logger;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Created by mphilpot on 7/24/14.
 */
public class URITest
{
    private static final Logger log = Logger.getLogger(URITest.class);

    @Test
    public void main() throws URISyntaxException
    {
        URI baseUrl = URI.create("http://localhost:8080");

        URI url = new URIBuilder(baseUrl).setPath("/authenticate").setPath("domain").setPath("bob").build();

        System.out.println(url);
    }
}
