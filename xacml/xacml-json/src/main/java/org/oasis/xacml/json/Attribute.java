package org.oasis.xacml.json;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/18/14.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Attribute
{
    private static final Logger log = Logger.getLogger(Attribute.class);

    @JsonProperty(value = "AttributeId", required = true)
    private String attributeId;

    @JsonProperty(value = "Value", required = true)
    private String value;

    @JsonProperty(value = "Issuer")
    private String issuer;

    @JsonProperty(value = "DataType")
    private String dataType;

    @JsonProperty(value = "IncludeInResult") // Used in request
    private Boolean includeInResult;

    @JsonProperty(value = "Category") // Used in response
    private String category;

    public String getAttributeId()
    {
        return attributeId;
    }

    public void setAttributeId(String attributeId)
    {
        this.attributeId = attributeId;
    }

    public String getValue()
    {
        return value;
    }

    public void setValue(String value)
    {
        this.value = value;
    }

    public String getIssuer()
    {
        return issuer;
    }

    public void setIssuer(String issuer)
    {
        this.issuer = issuer;
    }

    public String getDataType()
    {
        return dataType;
    }

    public void setDataType(String dataType)
    {
        this.dataType = dataType;
    }

    public Boolean getIncludeInResult()
    {
        return includeInResult;
    }

    public void setIncludeInResult(Boolean includeInResult)
    {
        this.includeInResult = includeInResult;
    }

    public String getCategory()
    {
        return category;
    }

    public void setCategory(String category)
    {
        this.category = category;
    }
}
