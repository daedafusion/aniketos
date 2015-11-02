package org.oasis.xacml.json.categories;

import org.oasis.xacml.json.Attribute;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by mphilpot on 7/18/14.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public class Category
{
    private static final Logger log = Logger.getLogger(Category.class);

    @JsonProperty(value = "CategoryId", required = true)
    private String categoryId;

    @JsonProperty(value = "Id")
    private String id;

    @JsonProperty(value = "Content")
    private String content;

    @JsonProperty(value = "Attribute")
    private List<Attribute> attributes;

    public Category()
    {
        // Empty
    }

    protected Category(String categoryId)
    {
        this.categoryId = categoryId;
    }

    public String getCategoryId()
    {
        return categoryId;
    }

    public void setCategoryId(String categoryId)
    {
        this.categoryId = categoryId;
    }

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public String getContent()
    {
        return content;
    }

    public void setContent(String content)
    {
        this.content = content;
    }

    public List<Attribute> getAttributes()
    {
        if(attributes == null)
            attributes = new ArrayList<>();

        return attributes;
    }

    public void setAttributes(List<Attribute> attributes)
    {
        this.attributes = attributes;
    }
}
