package org.oasis.xacml.json;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/18/14.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IdReference
{
    private static final Logger log = Logger.getLogger(IdReference.class);

    @JsonProperty(value = "Id", required = true)
    private String id;

    @JsonProperty(value = "Version")
    private String version;

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public String getVersion()
    {
        return version;
    }

    public void setVersion(String version)
    {
        this.version = version;
    }
}
