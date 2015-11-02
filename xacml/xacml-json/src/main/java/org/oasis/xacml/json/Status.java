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
public class Status
{
    private static final Logger log = Logger.getLogger(Status.class);

    @JsonProperty(value = "StatusMessage")
    private String statusMessage;

    @JsonProperty(value = "StatusDetail")
    private String statusDetail;

    @JsonProperty(value = "StatusCode")
    private List<StatusCode> statusCodes;

    public String getStatusMessage()
    {
        return statusMessage;
    }

    public void setStatusMessage(String statusMessage)
    {
        this.statusMessage = statusMessage;
    }

    public String getStatusDetail()
    {
        return statusDetail;
    }

    public void setStatusDetail(String statusDetail)
    {
        this.statusDetail = statusDetail;
    }

    public List<StatusCode> getStatusCodes()
    {
        if(statusCodes == null)
            statusCodes = new ArrayList<>();

        return statusCodes;
    }

    public void setStatusCodes(List<StatusCode> statusCodes)
    {
        this.statusCodes = statusCodes;
    }
}
