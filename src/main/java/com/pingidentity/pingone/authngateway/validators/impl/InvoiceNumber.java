package com.pingidentity.pingone.authngateway.validators.impl;

import javax.annotation.PostConstruct;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.pingidentity.pingone.authngateway.exceptions.CustomAPIErrorException;
import com.pingidentity.pingone.authngateway.validators.IValidator;
import com.pingidentity.pingone.authngateway.validators.ValidatorRegister;

@Component
public class InvoiceNumber implements IValidator {

	private static Logger log = LoggerFactory.getLogger(InvoiceNumber.class);

	@Value("${ping.customValidators.invoiceNumberValidator.attributeName}")
	private String attributeName;

	@Value("${ping.customValidators.invoiceNumberValidator.uiField}")
	private String uiField;
	
	@Autowired
	private ValidatorRegister registeredValidators;
	

	@PostConstruct
	public void init()
	{
		registeredValidators.register(this);
		
		if(uiField == null || uiField.trim().equals(""))
			uiField = attributeName;
	}

	@Override
	public void validate(JSONObject retainedValues, JSONObject requestPayload) throws CustomAPIErrorException {
		if (log.isDebugEnabled())
			log.debug(String.format("Validating: \nClaim: %s\nretainedValues: %s\nrequestPayload: %s", attributeName,
					retainedValues.toString(4), requestPayload.toString(4)));

		if (!requestPayload.has(attributeName))
			throw new CustomAPIErrorException(uiField, "INVALID_DATA",
					"The request could not be completed. One or more validation errors were in the request.", "INVALID_VALUE",
					"must be at least 1 characters long");

		String attributeValue = requestPayload.getString(attributeName);

		String email = retainedValues.getString("username");

		if (!attributeValue.contains(email.substring(0, email.indexOf("@"))))
			throw new CustomAPIErrorException(uiField, "INVALID_DATA",
					"The request could not be completed. One or more validation errors were in the request.", "INVALID_VALUE",
					"Invoice does not match the registered user");
	}

	@Override
	public boolean isApplicable(JSONObject userRequestPayload) {
		if(userRequestPayload == null)
			return false;
		
		return userRequestPayload.has(this.attributeName);
	}

	@Override
	public String info() {
		// TODO Auto-generated method stub
		return InvoiceNumber.class.getCanonicalName() + ":" + this.attributeName;
	}

}
