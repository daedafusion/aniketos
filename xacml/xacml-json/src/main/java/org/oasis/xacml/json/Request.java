package org.oasis.xacml.json;

import org.oasis.xacml.json.categories.Category;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by mphilpot on 7/18/14.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Request
{
    private static final Logger log = Logger.getLogger(Request.class);

    @JsonProperty(value = "ReturnPolicyIdList")
    private Boolean returnPolicyIdList;

    @JsonProperty(value = "CombinedDecision")
    private Boolean combinedDecision;

    @JsonProperty(value = "XPathVersion")
    private String xpathVersion;

    @JsonProperty(value = "Category")
    private List<Category> categories;

    public Boolean getReturnPolicyIdList()
    {
        return returnPolicyIdList;
    }

    public void setReturnPolicyIdList(Boolean returnPolicyIdList)
    {
        this.returnPolicyIdList = returnPolicyIdList;
    }

    public Boolean getCombinedDecision()
    {
        return combinedDecision;
    }

    public void setCombinedDecision(Boolean combinedDecision)
    {
        this.combinedDecision = combinedDecision;
    }

    public String getXpathVersion()
    {
        return xpathVersion;
    }

    public void setXpathVersion(String xpathVersion)
    {
        this.xpathVersion = xpathVersion;
    }

    public List<Category> getCategories()
    {
        if(categories == null)
            categories = new ArrayList<>();

        return categories;
    }

    public void setCategories(List<Category> categories)
    {
        this.categories = categories;
    }
}
