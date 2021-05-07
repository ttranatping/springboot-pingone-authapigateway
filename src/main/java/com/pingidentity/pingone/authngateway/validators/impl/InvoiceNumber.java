package com.pingidentity.pingone.authngateway.validators.impl;

import java.net.URISyntaxException;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pingidentity.pingone.authngateway.exceptions.CustomAPIErrorException;
import com.pingidentity.pingone.authngateway.validators.IValidator;

public class InvoiceNumber implements IValidator {

	private static Logger log = LoggerFactory.getLogger(InvoiceNumber.class);

	private final String attributeName;

	public InvoiceNumber(String attributeName, String authHost, String apiHost, String environmentId, String workerClientId,
			String workerClientSecret) throws URISyntaxException {
		this.attributeName = attributeName;
	}

	@Override
	public void validate(JSONObject retainedValues, JSONObject requestPayload) throws CustomAPIErrorException {
		if (log.isDebugEnabled())
			log.debug(String.format("Validating: \nClaim: %s\nretainedValues: %s\nrequestPayload: %s", attributeName,
					retainedValues.toString(4), requestPayload.toString(4)));

		if (!requestPayload.has(attributeName))
			throw new CustomAPIErrorException(attributeName, "BAD_CONFIG", "Missing Invoice Number", "BAD_CONFIG",
					"Missing Invoice Number");

		String attributeValue = requestPayload.getString(attributeName);

		String email = retainedValues.getString("email");

		if (!attributeValue.contains(email.substring(0, email.indexOf("@"))))
			throw new CustomAPIErrorException(attributeName, "BAD_INVOICE",
					"Invoice does not match the registered user", "BAD_INVOICE",
					"Invoice does not match the registered user");
	}

}
