package com.pingidentity.pingone.authngateway.controllers;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;

import com.pingidentity.pingone.authngateway.exceptions.CustomAPIErrorException;
import com.pingidentity.pingone.authngateway.exceptions.EncryptionException;
import com.pingidentity.pingone.authngateway.validators.IValidator;

@Controller
@RequestMapping("/")
public class PingOneAuthGatewayController {
	
	private static Logger log = LoggerFactory.getLogger(PingOneAuthGatewayController.class);

	@Value("${ping.authHost}")
	private String authHost;
	
	@Value("${ping.customValidators}")
	private String[] customValidators;
	
	@Value("${ping.retainValues.claims}")
	private String[] retainValues;
	
	@Value("${ping.obfuscateValues}")
	private String[] obfuscateValues;
	
	@Value("${ping.retainValues.encryptionKey}")
	private String encryptionKey;
	
	@Value("${ping.environmentId}")
	private String environmentId;
	
	private EncryptionHelper encryptionHelper;

	private HttpClient httpClient = null;
	
	private Map<String, List<IValidator>> claimValidators = new HashMap<String, List<IValidator>>(); 

	@PostConstruct
	public void init() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, EncryptionException, ClassNotFoundException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException {
		
		httpClient = HttpClient.newBuilder()
			      .version(HttpClient.Version.HTTP_2)
			      .followRedirects(HttpClient.Redirect.NEVER)
			      .build();
		
		for(String customValidator: customValidators)
		{
			log.info("Registering customValidator: " + customValidator);
			
			String [] customValidatorSplit = customValidator.split("\\|");
			
			String claimName = customValidatorSplit[0];
			String validatorClass = customValidatorSplit[1];
			
			log.info("Validator class: " + validatorClass);
			
			Class<?> classForValidator = Class.forName(validatorClass);
			IValidator validator = (IValidator) classForValidator.getConstructor(new Class[] {String.class}).newInstance(claimName);
			
			List<IValidator> validatorList = claimValidators.containsKey(claimName)?claimValidators.get(claimName):new ArrayList<IValidator>();
			validatorList.add(validator);
			
			claimValidators.put(claimName, validatorList);
			
			log.info("Successfully registered validator");
		}
		
		log.info("Registering encryptionKey: " + encryptionKey);
		
		this.encryptionHelper = new EncryptionHelper(encryptionKey, environmentId, retainValues);
	}

	@GetMapping("/{envId}/as/authorize")
	public void authorize(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers,
			@PathVariable(value = "envId", required = true) String envId) throws IOException, InterruptedException, URISyntaxException {

		if(log.isDebugEnabled())
			log.debug("Process Authorize Endpoint");
		
		Builder targetRequestBuilder = HttpRequest.newBuilder().uri(getTargetUrl(request)).GET();

		copyRequestHeaders(headers, request, targetRequestBuilder);

		HttpRequest targetRequest = targetRequestBuilder.build();
		
		HttpResponse<String> targetResponse = executeTargetRequest(targetRequest, response, false);

		String location = getLocationHeader(targetResponse, response);

		if(log.isDebugEnabled())
			log.debug("Location header: " + location);
		
		response.sendRedirect(location);
		response.setStatus(302);
		response.addHeader(":status", "302");
	}

	@GetMapping(value = "/{envId}/**", produces = "application/hal+json;charset=UTF-8")
	public ResponseEntity<String> get(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers,
			@PathVariable(value = "envId", required = true) String envId) throws IOException, InterruptedException, URISyntaxException {

		if(log.isDebugEnabled())
			log.debug("Process GET");
		
		Builder targetRequestBuilder = HttpRequest.newBuilder().uri(getTargetUrl(request)).GET();

		copyRequestHeaders(headers, request, targetRequestBuilder);

		HttpRequest targetRequest = targetRequestBuilder.build();
		
		HttpResponse<String> targetResponse = executeTargetRequest(targetRequest, response);

		String responsePayload = getResponsePayload(targetResponse);

		return new ResponseEntity<String>(responsePayload,
				HttpStatus.valueOf(targetResponse.statusCode()));
	}
	
	private String getLocationHeader(HttpResponse<String> targetResponse, HttpServletResponse response) throws IOException, InterruptedException
	{
		List<String> locationHeader = targetResponse.headers().map().get("location");
		
		if(locationHeader != null && locationHeader.size() == 1)
		{
			String location = locationHeader.get(0);				
			
			return location;
		}
		
		throw new InterruptedException("HTTP 302 Status found with no location header");
	}

	@PostMapping(value = "/{envId}/flows/{flowId}", produces = "application/hal+json;charset=UTF-8")
	public ResponseEntity<String> post(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers, @RequestBody(required = true) String bodyStr,
			@PathVariable(value = "envId", required = true) String envId,
			@PathVariable(value = "flowId", required = true) String flowId) throws IOException, URISyntaxException, InterruptedException, EncryptionException, CustomAPIErrorException {

		if(log.isDebugEnabled())
			log.debug(String.format("Process POST - FlowId: %s, with body: %s", flowId, obfuscate(bodyStr)));
		
		JSONObject retainedValues = updateRetainedValues(request, response, flowId, bodyStr);
		
		validateRequestPayload(retainedValues, bodyStr);
		
		Builder targetRequestBuilder = HttpRequest.newBuilder().uri(getTargetUrl(request)).POST(BodyPublishers.ofString(bodyStr));

		copyRequestHeaders(headers, request, targetRequestBuilder);

		HttpRequest targetRequest = targetRequestBuilder.build();
		
		HttpResponse<String> targetResponse = executeTargetRequest(targetRequest, response);
		
		String responsePayload = getResponsePayload(targetResponse);
		
		return new ResponseEntity<String>(responsePayload,
				HttpStatus.valueOf(targetResponse.statusCode()));
	}

	private void validateRequestPayload(JSONObject retainedValues, String bodyStr) throws CustomAPIErrorException {

		JSONObject requestPayload = new JSONObject(bodyStr);
		JSONObject userRequestPayload = requestPayload.has("user")?requestPayload.getJSONObject("user"):requestPayload;
		
		for(String validatorClaim: this.claimValidators.keySet())
		{
			if(userRequestPayload.has(validatorClaim))
			{
				for(IValidator validator : this.claimValidators.get(validatorClaim))
					validator.validate(retainedValues, userRequestPayload);
			}
		}
		
	}

	private String obfuscate(String bodyStr) {
		JSONObject jsonObject = new JSONObject(bodyStr);
		
		for(String obfuscateClaim: this.obfuscateValues)
		{
			if(jsonObject.has(obfuscateClaim))
				jsonObject.put(obfuscateClaim, "****");
		}
			
		return jsonObject.toString(4);
	}

	private JSONObject updateRetainedValues(HttpServletRequest request, HttpServletResponse response, String flowId, String bodyStr) throws EncryptionException {
		JSONObject jsonPayload = new JSONObject(bodyStr);
		
		JSONObject cookieValues = getRetainedValuesFromCookie(flowId, request);
		
		for(String retainValue: this.retainValues)
		{
			if(!jsonPayload.has(retainValue))
				continue;
			
			cookieValues.put(retainValue, jsonPayload.get(retainValue));
		}
		
		String newEncryptedCookieValue = this.encryptionHelper.generate(flowId, cookieValues);
		
		Cookie newEncryptedCookie = new Cookie(getCookieName(flowId), newEncryptedCookieValue);		
		response.addCookie(newEncryptedCookie);
		
		if(log.isDebugEnabled())
			log.debug("Retained Values: " + cookieValues.toString(4));
		
		return cookieValues;
	}

	private JSONObject getRetainedValuesFromCookie(String flowId, HttpServletRequest request) throws EncryptionException {
		if(request.getCookies() == null)
			return new JSONObject();
		
		for(Cookie cookie: request.getCookies())
		{
			if(!cookie.getName().equals(getCookieName(flowId)))
				continue;
			
			return this.encryptionHelper.read(flowId, cookie.getValue());
		}
		
		return new JSONObject();
	}

	private String getCookieName(String flowId) {
		return "ST-RC-" + flowId;
	}

	private URI getTargetUrl(HttpServletRequest request) throws URISyntaxException {
		String url = null;
		if(!StringUtils.isEmpty(request.getQueryString()))
			url = String.format("https://%s%s?%s", this.authHost, request.getRequestURI(), request.getQueryString());
		else
			url = String.format("https://%s%s", this.authHost, request.getRequestURI());
		
		if(log.isDebugEnabled())
			log.debug("Target URL: " + url);
		
		return new URI(url);
	}

	private void copyRequestHeaders(MultiValueMap<String, String> headers, HttpServletRequest request, Builder targetRequestBuilder) {
					
	    headers.forEach((key, values) -> {
	    	
	    	key = key.toLowerCase();
	    	
	    	if(!key.equals("host") && !key.equals("connection") && !key.equals("content-length"))
	    	{
	    		if(log.isDebugEnabled())
			    	log.debug(String.format(
			          "Header '%s' = %s", key, values.stream().collect(Collectors.joining("|"))));
		        
		        for(String value : values)
		        	targetRequestBuilder.header(key, value);
	    	}
	    });
	    
	}

	private String getResponsePayload(HttpResponse<String> response) throws UnsupportedOperationException, IOException {
		if (response == null) {
			return null;
		}
		
		if(log.isDebugEnabled())
			log.trace("Getting body");

		if (response.statusCode() == 204 || response.statusCode() == 302 || response.body() == null) {
			if(log.isDebugEnabled())
				log.debug("No body");
			return "";
		} else {
			String body = response.body();

			if(log.isDebugEnabled())
				log.debug("Body: " + body);
			
			return body;
		}

	}
	private HttpResponse<String> executeTargetRequest(HttpRequest targetRequest, HttpServletResponse response) throws IOException, InterruptedException {
		return executeTargetRequest(targetRequest, response, true);
	}

	private HttpResponse<String> executeTargetRequest(HttpRequest targetRequest, HttpServletResponse response, boolean isSetResponseHeaders) throws IOException, InterruptedException {

		HttpResponse<String> targetResponse = httpClient.send(targetRequest, BodyHandlers.ofString());
		
		if(isSetResponseHeaders)
		{
			for(String headerName: targetResponse.headers().map().keySet())
			{				
				if(headerName.equalsIgnoreCase(":status") || headerName.equalsIgnoreCase("content-type") || headerName.equalsIgnoreCase("content-length") || headerName.toLowerCase().startsWith("access-control"))
					continue;
				
				for(String headerValue: targetResponse.headers().allValues(headerName))
				{
					if(log.isDebugEnabled())
						log.debug(String.format("Adding response header: %s=%s", headerName, headerValue));
					response.addHeader(headerName, headerValue);
				}
			}
		}
		
		return targetResponse;
	}

}
