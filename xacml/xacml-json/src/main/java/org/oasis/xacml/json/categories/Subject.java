package org.oasis.xacml.json.categories;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/18/14.
 */
public class Subject extends Category
{
    private static final Logger log = Logger.getLogger(Subject.class);

    public Subject()
    {
        super("urn:oasis:names:tc:xacml:1.0:subject-category:access-subject");
    }
}
