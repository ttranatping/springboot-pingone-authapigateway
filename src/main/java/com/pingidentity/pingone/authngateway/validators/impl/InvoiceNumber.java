package com.pingidentity.pingone.authngateway.validators.impl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pingidentity.pingone.authngateway.exceptions.CustomAPIErrorException;
import com.pingidentity.pingone.authngateway.validators.IValidator;

public class InvoiceNumber implements IValidator {

	private static Logger log = LoggerFactory.getLogger(InvoiceNumber.class);

	private final String attributeName;
	private final String authHost;
	private final String apiHost;
	private final String environmentId;
	private final String workerClientId;
	private final String workerClientSecret;
	private final URI tokenEndpoint;
	private final String userAPIEndpoint;
	private String accessToken = null;

	private final HttpClient httpClient;

	public InvoiceNumber(String attributeName, String authHost, String apiHost, String environmentId, String workerClientId,
			String workerClientSecret) throws URISyntaxException {
		this.attributeName = attributeName;
		this.authHost = authHost;
		this.apiHost = apiHost;
		this.environmentId = environmentId;
		this.workerClientId = workerClientId;
		this.workerClientSecret = workerClientSecret;

		this.tokenEndpoint = new URI(String.format("https://%s/%s/as/token", this.authHost, this.environmentId));
		this.userAPIEndpoint = String.format("https://%s/v1/environments/%s/users", this.apiHost, this.environmentId);

		this.httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2)
				.followRedirects(HttpClient.Redirect.NEVER).build();
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

		String username = retainedValues.getString("username");

		enableMFA(username);
	}

	private void enableMFA(String username) throws CustomAPIErrorException {
		createAccessToken();

		String userId = getUserId(username);
		
		//{{apiPath}}/environments/{{envID}}/users/{{userID-1}}/mfaEnabled
		

		
		Builder targetRequestBuilder = null;
		
		String searchEndpoint = this.userAPIEndpoint + "/" + userId + "/mfaEnabled";
		
		if(log.isDebugEnabled())
			log.debug("User search endpoint: " + searchEndpoint);
		
		String payload = "{\n" + 
				"    \"mfaEnabled\": true\n" + 
				"}";
		
		try {
			targetRequestBuilder = HttpRequest.newBuilder().uri(new URI(searchEndpoint))
					.PUT(BodyPublishers.ofString(payload));
		} catch (URISyntaxException e) {
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue. Unable to create http builder for enabling MFA.");
		}

		targetRequestBuilder.setHeader("content-type", "application/json");
		targetRequestBuilder.setHeader("Authorization", "Bearer " + this.accessToken);
		
		HttpRequest targetRequest = targetRequestBuilder.build();

		HttpResponse<String> targetResponse = null;
		
		try {
			targetResponse = httpClient.send(targetRequest, BodyHandlers.ofString());
		} catch (IOException | InterruptedException e) {
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue trying to enable mfa for user.");

		}
		
		if(targetResponse.statusCode() != 200)
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue. Bad http response when enabling MFA for user: " + targetResponse.statusCode());
		
	}
	
	private String getUserId(String username) throws CustomAPIErrorException
	{
		String filter = null;
		try {
			filter = "filter=" + URLEncoder.encode(String.format("username eq \"%s\"", username), "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue. Unable to create search filter for user.");
		}
		
		Builder targetRequestBuilder = null;
		
		String searchEndpoint = this.userAPIEndpoint + "?" + filter;
		
		if(log.isDebugEnabled())
			log.debug("User search endpoint: " + searchEndpoint);
		
		try {
			targetRequestBuilder = HttpRequest.newBuilder().uri(new URI(searchEndpoint)).GET();
		} catch (URISyntaxException e) {
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue. Unable to create http builder for user.");
		}

		targetRequestBuilder.setHeader("content-type", "application/json");
		targetRequestBuilder.setHeader("Authorization", "Bearer " + this.accessToken);
		
		HttpRequest targetRequest = targetRequestBuilder.build();

		HttpResponse<String> targetResponse = null;
		
		try {
			targetResponse = httpClient.send(targetRequest, BodyHandlers.ofString());
		} catch (IOException | InterruptedException e) {
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue trying to search for user.");

		}

		String responsePayload = null;

		try {
			responsePayload = getResponsePayload(targetResponse);
		} catch (UnsupportedOperationException | IOException e) {
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue. Cannot receive access token response");
		}
		
		if(log.isDebugEnabled())
			log.debug("Search response: " + responsePayload);
		
		JSONObject userResponse = new JSONObject(responsePayload);

		if (!userResponse.has("size"))
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue. Cannot obtain size of response.");
		
		int size = userResponse.getInt("size");
		
		if(size != 1)
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Ambiguous user. Please contact support",
					"UNKNOWN", "Ambiguous user. Expected 1 result.");
		
		Object idObject = userResponse.query("/_embedded/users/0/id");
		
		if(idObject == null)
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Ambiguous user. Please contact support",
					"UNKNOWN", "Ambiguous user. Could not determine id value for user.");
		
		if(log.isDebugEnabled())
			log.debug("User ID Value: " + idObject);
		
		return String.valueOf(idObject);
	}

	private void createAccessToken() throws CustomAPIErrorException {		
		String payload = String.format("grant_type=client_credentials&client_id=%s&client_secret=%s", this.workerClientId, this.workerClientSecret);
		
		Builder targetRequestBuilder = HttpRequest.newBuilder().uri(this.tokenEndpoint)
				.POST(BodyPublishers.ofString(payload));

		targetRequestBuilder.header("content-type", "application/x-www-form-urlencoded");
		HttpRequest targetRequest = targetRequestBuilder.build();

		HttpResponse<String> targetResponse = null;

		try {
			targetResponse = httpClient.send(targetRequest, BodyHandlers.ofString());
		} catch (IOException | InterruptedException e) {
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue.");

		}
		
		if(targetResponse.statusCode() != 200)
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue. Bad http response when retrieving access token: " + targetResponse.statusCode());

		String responsePayload = null;

		try {
			responsePayload = getResponsePayload(targetResponse);
		} catch (UnsupportedOperationException | IOException e) {
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue. Cannot receive access token response");
		}
		
		if(log.isDebugEnabled())
			log.debug("AT response: " + responsePayload);

		JSONObject atResponse = new JSONObject(responsePayload);

		if (!atResponse.has("access_token"))
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue. Cannot locate access_token.");
		
		this.accessToken = atResponse.getString("access_token");
	}

	private String getResponsePayload(HttpResponse<String> response) throws UnsupportedOperationException, IOException {
		if (response == null) {
			return null;
		}

		if (log.isDebugEnabled())
			log.trace("Getting body");

		if (response.statusCode() == 204 || response.statusCode() == 302 || response.body() == null) {
			if (log.isDebugEnabled())
				log.debug("No body");
			return "";
		} else {
			String body = response.body();

			if (log.isDebugEnabled())
				log.debug("Body: " + body);

			return body;
		}

	}

}
