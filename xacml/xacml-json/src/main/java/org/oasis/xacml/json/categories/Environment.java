package org.oasis.xacml.json.categories;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/18/14.
 */
public class Environment extends Category
{
    private static final Logger log = Logger.getLogger(Environment.class);

    public Environment()
    {
        super("urn:oasis:names:tc:xacml:3.0:attribute-category:environment");
    }
}
