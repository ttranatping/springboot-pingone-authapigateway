package com.pingidentity.pingone.authngateway.validators;

import java.util.Map;

import org.json.JSONObject;

import com.pingidentity.pingone.authngateway.exceptions.CustomAPIErrorException;

public interface IValidator {

	public void validate(Map<String, Object> retainedValues, Map<String, Object> requestPayload) throws CustomAPIErrorException;
	public boolean isApplicable(Map<String, Object> userRequestPayload);
	public String info();
}
