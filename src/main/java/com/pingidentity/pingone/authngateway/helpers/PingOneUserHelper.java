package com.pingidentity.pingone.authngateway.helpers;

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
import java.util.Date;

import javax.annotation.PostConstruct;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.pingidentity.pingone.authngateway.exceptions.CustomAPIErrorException;

@Component
public class PingOneUserHelper {

	private static Logger log = LoggerFactory.getLogger(PingOneUserHelper.class);

	private String attributeName;

	@Value("${ping.authHost}")
	private String authHost;

	@Value("${ping.apiHost}")
	private String apiHost;

	@Value("${ping.environmentId}")
	private String environmentId;

	@Value("${oauth2.worker.clientId}")
	private String workerClientId;

	@Value("${oauth2.worker.clientSecret}")
	private String workerClientSecret;

	private URI tokenEndpoint;
	private String userAPIEndpoint;
	private String accessToken = null;
	private Long accessTokenExpiresIn = null;

	private HttpClient httpClient;

	@PostConstruct
	public void init() throws URISyntaxException {
		this.attributeName = "enablemfa";

		this.tokenEndpoint = new URI(String.format("https://%s/as/token", this.authHost, this.environmentId));
		this.userAPIEndpoint = String.format("https://%s/v1/environments/%s/users", this.apiHost, this.environmentId);

		this.httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2)
				.followRedirects(HttpClient.Redirect.NEVER).build();
	}

	public boolean enableMFA(String username, String retainValueKey) throws CustomAPIErrorException {
		createAccessToken();
		
		String userId = getUserId(username, retainValueKey);

		if (userId == null)
			return false;

		Builder targetRequestBuilder = null;

		String searchEndpoint = this.userAPIEndpoint + "/" + userId + "/mfaEnabled";

		if (log.isDebugEnabled())
			log.debug("User search endpoint: " + searchEndpoint);

		String payload = "{\n" + "    \"mfaEnabled\": true\n" + "}";

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
			log.error("Unknown issue. Bad http response when enabling MFA for user", e);
			return false;
		}

		if (targetResponse.statusCode() != 200) {
			log.error("Bad status code when enabling MFA: " + 200);
			return false;
		}

		return true;

	}

	public String getUserId(String searchValue, String searchKey) throws CustomAPIErrorException {
		createAccessToken();
		
		return getUser(searchValue, searchKey).getString("id");
	}

	public String getUserName(String searchValue, String searchKey) throws CustomAPIErrorException {
		createAccessToken();
		
		return getUser(searchValue, searchKey).getString("username");
	}

	public JSONObject getUser(String searchValue, String searchKey) throws CustomAPIErrorException {
		createAccessToken();
		
		String filter = null;
		try {
			filter = "filter=" + URLEncoder.encode(String.format(searchKey + " eq \"%s\"", searchValue), "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue. Unable to create search filter for user.");
		}

		String searchEndpoint = this.userAPIEndpoint + "?" + filter;

		if (log.isDebugEnabled())
			log.debug("User search endpoint: " + searchEndpoint);

		JSONObject userResponse = loadObject(searchEndpoint);

		if (userResponse == null)
			return null;

		Object idObject = userResponse.query("/_embedded/users/0");

		return (JSONObject) idObject;
	}

	public JSONObject getUserDevices(String userId) throws CustomAPIErrorException {
		createAccessToken();
		
		String endpoint = String.format("%s/%s/devices", this.userAPIEndpoint, userId);

		String searchEndpoint = endpoint;

		if (log.isDebugEnabled())
			log.debug("User device search endpoint: " + searchEndpoint);

		return loadObject(endpoint);
	}

	public boolean registerEmailDevice(String username, String emailAttribute) throws CustomAPIErrorException {
		createAccessToken();
		
		String userId = getUserId(username, "username");

		if (userId == null)
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN",
					"Unknown issue registering email mfa. Please contact support", "UNKNOWN",
					"Unknown issue registering email mfa. UserId is null.");

		JSONObject userDevices = getUserDevices(userId);

		if (userDevices != null) {
			if (log.isDebugEnabled())
				log.debug("Skipping mfa enrolment because the user already has a device enabled.");

			return false;
		}

		String payload = "{\n" + "    \"type\": \"EMAIL\",\n" + "    \"email\": \"" + emailAttribute + "\"\n" + "}";

		Builder targetRequestBuilder = null;

		String endpoint = String.format("%s/%s/devices", this.userAPIEndpoint, userId);

		try {
			targetRequestBuilder = HttpRequest.newBuilder().uri(new URI(endpoint))
					.POST(BodyPublishers.ofString(payload));
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
			log.error("Unknown issue. Bad http response when enabling MFA for user", e);
			return false;
		}

		if (targetResponse.statusCode() != 201) {
			log.error("Bad status code when adding MFA device: " + 201);
			return false;
		}

		return true;
	}

	private void createAccessToken() throws CustomAPIErrorException {

		if (this.accessToken != null && this.accessTokenExpiresIn != null
				&& this.accessTokenExpiresIn > (new Date()).getTime()) {

			if(log.isDebugEnabled())
				log.debug("Using existing accessToken");
			return;
		}

		String payload = String.format("grant_type=client_credentials&client_id=%s&client_secret=%s",
				this.workerClientId, this.workerClientSecret);

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

		if (targetResponse.statusCode() != 200)
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN",
					"Unknown issue. Bad http response when retrieving access token: " + targetResponse.statusCode());

		String responsePayload = null;

		try {
			responsePayload = getResponsePayload(targetResponse);
		} catch (UnsupportedOperationException | IOException e) {
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue. Cannot receive access token response");
		}

		if (log.isDebugEnabled())
			log.debug("AT response: " + responsePayload);

		JSONObject atResponse = new JSONObject(responsePayload);

		if (!atResponse.has("access_token"))
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue. Cannot locate access_token.");

		if (atResponse.has("expires_in")) {
			Integer accessTokenExpires = atResponse.getInt("expires_in");
			if (accessTokenExpires != null) {
				// 750 = 1000ms less 25%
				this.accessTokenExpiresIn = (new Date()).getTime() + (accessTokenExpires * 750);
			}
		}

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

	private JSONObject loadObject(String endpoint) throws CustomAPIErrorException {

		Builder targetRequestBuilder = null;

		String searchEndpoint = endpoint;

		if (log.isDebugEnabled())
			log.debug("Search endpoint: " + searchEndpoint);

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

		if (log.isDebugEnabled())
			log.debug("Search response: " + responsePayload);

		JSONObject userResponse = new JSONObject(responsePayload);

		if (!userResponse.has("size"))
			throw new CustomAPIErrorException(this.attributeName, "UNKNOWN", "Unknown issue. Please contact support",
					"UNKNOWN", "Unknown issue. Cannot obtain size of response.");

		int size = userResponse.getInt("size");

		if (size != 1) {
			log.debug("Ambiguous user. Expected 1 result.");
			return null;
		}

		return userResponse;
	}

}
