package com.pingidentity.pingone.authngateway.validators;

import org.json.JSONObject;

import com.pingidentity.pingone.authngateway.exceptions.CustomAPIErrorException;

public interface IValidator {

	public void validate(JSONObject retainedValues, String requestPayload) throws CustomAPIErrorException;
}
