package com.pingidentity.pingone.authngateway.validators.impl;

import java.util.Map;

import javax.annotation.PostConstruct;

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

	@Value("${ping.customValidators.invoiceNumberValidator.emailField}")
	private String emailField;
	
	@Autowired
	private ValidatorRegister registeredValidators;
	

	@PostConstruct
	public void init()
	{
		registeredValidators.register(this);
		
		if(uiField == null || uiField.trim().equals(""))
			uiField = attributeName;
		
		if(emailField == null || emailField.trim().equals(""))
			emailField = "username";
	}

	@Override
	public void validate(Map<String, Object> retainedValues, Map<String, Object> userRequestPayload) throws CustomAPIErrorException {
		if (log.isDebugEnabled())
			log.debug(String.format("Validating: \nClaim: %s", attributeName));

		if (!userRequestPayload.containsKey(attributeName))
			throw new CustomAPIErrorException(uiField, "INVALID_DATA",
					"The request could not be completed. One or more validation errors were in the request.", "INVALID_VALUE",
					"must be at least 1 characters long");

		if (!retainedValues.containsKey(emailField))
			throw new CustomAPIErrorException(uiField, "INVALID_CONFIG",
					"The request could not be completed. ", "INVALID_CONFIG",
					"could not determine email address");

		String attributeValue = String.valueOf(userRequestPayload.get(attributeName));

		String email = String.valueOf(retainedValues.get(emailField));

		if (!attributeValue.contains(email.substring(0, email.indexOf("@"))))
			throw new CustomAPIErrorException(uiField, "INVALID_DATA",
					"The request could not be completed. One or more validation errors were in the request.", "INVALID_VALUE",
					"Invoice does not match the registered user");
	}

	@Override
	public boolean isApplicable(Map<String, Object> userRequestPayload) {
		if(userRequestPayload == null)
			return false;
		
		return userRequestPayload.containsKey(this.attributeName);
	}

	@Override
	public String info() {
		// TODO Auto-generated method stub
		return InvoiceNumber.class.getCanonicalName() + ":" + this.attributeName;
	}

}
