package com.pingidentity.pingone.authngateway.validators.impl;

import org.json.JSONObject;

import com.pingidentity.pingone.authngateway.exceptions.CustomAPIErrorException;
import com.pingidentity.pingone.authngateway.validators.IValidator;

public class InvoiceNumber implements IValidator {

	public InvoiceNumber(String attributeName)
	{
		
	}
	
	@Override
	public void validate(JSONObject retainedValues, String requestPayload) throws CustomAPIErrorException {
		// TODO Auto-generated method stub

	}

}
