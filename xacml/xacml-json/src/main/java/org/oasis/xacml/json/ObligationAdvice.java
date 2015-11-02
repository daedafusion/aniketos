package org.oasis.xacml.json;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by mphilpot on 7/18/14.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ObligationAdvice
{
    private static final Logger log = Logger.getLogger(ObligationAdvice.class);

    @JsonProperty(value = "Id", required = true)
    private String id;

    @JsonProperty(value = "AttributeAssignment")
    private List<Attribute> attributeAssignments;

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public List<Attribute> getAttributeAssignments()
    {
        if(attributeAssignments == null)
            attributeAssignments = new ArrayList<>();

        return attributeAssignments;
    }

    public void setAttributeAssignments(List<Attribute> attributeAssignments)
    {
        this.attributeAssignments = attributeAssignments;
    }
}
