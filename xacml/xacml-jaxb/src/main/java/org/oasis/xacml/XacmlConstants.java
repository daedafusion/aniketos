package org.oasis.xacml;

/**
 * Created by mphilpot on 7/29/14.
 */
public interface XacmlConstants
{
    // http://sunxacml.sourceforge.net/javadoc/constant-values.html

    public interface Categories
    {
        final String ACCESS_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
        final String RESOURCE = "urn:oasis:names:tc:xacml:3.0:attribute-category:resource";
        final String ACTION = "urn:oasis:names:tc:xacml:3.0:attribute-category:action";
    }

    public interface  Attributes
    {
        final String SUBJECT_ID = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
        final String RESOURCE_ID = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
        final String ACTION_ID = "urn:oasis:names:tc:xacml:1.0:action:action-id";
    }

    public interface DataTypes
    {
        final String STRING = "http://www.w3.org/2001/XMLSchema#string";
        final String B64_BINARY = "http://www.w3.org/2001/XMLSchema#base64Binary";
        final String HEX_BINARY = "http://www.w3.org/2001/XMLSchema#hexBinary";
        final String BOOLEAN = "http://www.w3.org/2001/XMLSchema#boolean";
        final String DATE = "http://www.w3.org/2001/XMLSchema#date";
        final String DATETIME = "http://www.w3.org/2001/XMLSchema#dateTime";
        final String TIME = "http://www.w3.org/2001/XMLSchema#time";
        final String DOUBLE = "http://www.w3.org/2001/XMLSchema#double";
        final String INTEGER = "http://www.w3.org/2001/XMLSchema#integer";
    }
}
