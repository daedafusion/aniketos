package org.oasis.xacml.json.categories;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/18/14.
 */
public class Resource extends Category
{
    private static final Logger log = Logger.getLogger(Resource.class);

    public Resource()
    {
        super("urn:oasis:names:tc:xacml:3.0:attribute-category:resource");
    }
}
