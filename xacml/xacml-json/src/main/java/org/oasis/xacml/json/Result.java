package org.oasis.xacml.json;

import org.oasis.xacml.json.categories.Category;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by mphilpot on 7/18/14.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Result
{
    private static final Logger log = Logger.getLogger(Result.class);

    @JsonIgnore
    public static final String Permit        = "Permit";
    @JsonIgnore
    public static final String Deny          = "Deny";
    @JsonIgnore
    public static final String NotApplicable = "NotApplicable";
    @JsonIgnore
    public static final String Indeterminate = "Indeterminate";

    @JsonProperty(value = "Decision", required = true)
    private String decision;

    @JsonProperty(value = "Status")
    private Status status;

    @JsonProperty(value = "Obligations")
    private List<ObligationAdvice> obligations;

    @JsonProperty(value = "AssociatedAdvice")
    private List<ObligationAdvice> associatedAdvice;

    @JsonProperty(value = "Attributes") // WTF?!
    private List<Category> attributes;

    @JsonProperty(value = "PolicyIdentifier")
    private PolicyIdentifier policyIdentifier;

    public String getDecision()
    {
        return decision;
    }

    public void setDecision(String decision)
    {
        this.decision = decision;
    }

    public Status getStatus()
    {
        return status;
    }

    public void setStatus(Status status)
    {
        this.status = status;
    }

    public List<ObligationAdvice> getObligations()
    {
        if(obligations == null)
            obligations = new ArrayList<>();

        return obligations;
    }

    public void setObligations(List<ObligationAdvice> obligations)
    {
        this.obligations = obligations;
    }

    public List<ObligationAdvice> getAssociatedAdvice()
    {
        if(associatedAdvice == null)
            associatedAdvice = new ArrayList<>();

        return associatedAdvice;
    }

    public void setAssociatedAdvice(List<ObligationAdvice> associatedAdvice)
    {
        this.associatedAdvice = associatedAdvice;
    }

    public List<Category> getAttributes()
    {
        if(attributes == null)
            attributes = new ArrayList<>();

        return attributes;
    }

    public void setAttributes(List<Category> attributes)
    {
        this.attributes = attributes;
    }

    public PolicyIdentifier getPolicyIdentifier()
    {
        return policyIdentifier;
    }

    public void setPolicyIdentifier(PolicyIdentifier policyIdentifier)
    {
        this.policyIdentifier = policyIdentifier;
    }
}
