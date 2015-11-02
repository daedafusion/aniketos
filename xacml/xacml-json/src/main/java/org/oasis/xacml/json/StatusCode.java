package org.oasis.xacml.json;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/18/14.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class StatusCode
{
    private static final Logger log = Logger.getLogger(StatusCode.class);

    @JsonProperty(value = "Value")
    private String value;

    public String getValue()
    {
        return value;
    }

    public void setValue(String value)
    {
        this.value = value;
    }
}
