package com.pingidentity.pingone.authngateway.controllers;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.pingidentity.pingone.authngateway.exceptions.CustomAPIErrorException;
import com.pingidentity.pingone.authngateway.exceptions.EncryptionException;
import com.pingidentity.pingone.authngateway.validators.IValidator;
import com.pingidentity.pingone.authngateway.validators.ValidatorRegister;

@Controller
@RequestMapping("/")
public class PingOneAuthGatewayController {
	
	private static Logger log = LoggerFactory.getLogger(PingOneAuthGatewayController.class);

	@Autowired
	private ValidatorRegister registeredValidators;

	@Value("${ping.authHost}")
	private String authHost;
	
	@Value("${ping.retainValues.claims}")
	private String[] retainValues;
	
	@Value("${ping.obfuscateValues}")
	private String[] obfuscateValues;
	
	@Autowired
	private EncryptionHelper encryptionHelper;

	private HttpClient httpClient = null;
	
	@Autowired
	private UserEnableMFA enableUserMFA;

	@PostConstruct
	public void init() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, EncryptionException, ClassNotFoundException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException, URISyntaxException {
		
		httpClient = HttpClient.newBuilder()
			      .version(HttpClient.Version.HTTP_2)
			      .followRedirects(HttpClient.Redirect.NEVER)
			      .build();
		
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
		
		HttpResponse<InputStream> targetResponse = executeTargetRequest(targetRequest, response, false);

		String location = getLocationHeader(targetResponse, response);

		if(log.isDebugEnabled())
			log.debug("Location header: " + location);
		
		response.sendRedirect(location);
		response.setStatus(302);
		response.addHeader(":status", "302");
	}

	@GetMapping(value = "/{envId}/experiences/{experienceId}", produces = "text/html;charset=UTF-8")
	public ResponseEntity<String> getExperiences(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers,
			@PathVariable(value = "envId", required = true) String envId,
			@RequestParam String redirectUri) throws IOException, InterruptedException, URISyntaxException {

		String flowId = redirectUri.substring(redirectUri.indexOf("/flows/") + "/flows/".length()).replace("flowExecutionCallback", "").replaceAll("\\/", "");

		if(log.isDebugEnabled())
			log.debug("Process getExperiences flowId: " + flowId);
		
		return performGET(request, response, headers, envId);
	}

	@GetMapping(value = "/{envId}/flows/{flowId}/flowExecutionCallback", produces = "text/html;charset=UTF-8")
	public ResponseEntity<String> getFlowExecutionCallback(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers,
			@PathVariable(value = "envId", required = true) String envId,
			@PathVariable(value = "flowId", required = true) String flowId,
			@RequestParam String flowExecutionId) throws IOException, InterruptedException, URISyntaxException, EncryptionException {

		if(log.isDebugEnabled())
			log.debug("Process getFlowExecutionCallback flowId: " + flowId);
		
		//copying flow execution cookie to flow cookie
		JSONObject cookieValues = getRetainedValuesFromCookie(flowExecutionId, request);
		if(cookieValues != null)
		{
			if(log.isDebugEnabled())
				log.debug("copying flow execution cookie to flow cookie");
			
			String newEncryptedCookieValue = this.encryptionHelper.generate(flowId, cookieValues);
			addCookie(this.getCookieName(flowId), newEncryptedCookieValue, response);
		}
		
		return performGET(request, response, headers, envId);
	}

	@GetMapping(value = "/{envId}/**", produces = "application/hal+json;charset=UTF-8")
	public ResponseEntity<String> get(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers,
			@PathVariable(value = "envId", required = true) String envId) throws IOException, InterruptedException, URISyntaxException {

		if(log.isDebugEnabled())
			log.debug("Process GET");
		
		return performGET(request, response, headers, envId);
	}

	@PostMapping(value = "/{envId}/flows/{flowId}", produces = "application/hal+json;charset=UTF-8")
	public ResponseEntity<String> post(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers, @RequestBody(required = true) String bodyStr,
			@PathVariable(value = "envId", required = true) String envId,
			@PathVariable(value = "flowId", required = true) String flowId) throws IOException, URISyntaxException, InterruptedException, EncryptionException, CustomAPIErrorException {

		if(log.isDebugEnabled())
			log.debug(String.format("Process POST - FlowId: %s, with body: %s", flowId, obfuscate(bodyStr)));
		
		if(log.isDebugEnabled())
			log.debug(String.format("Process POST - FlowId: %s, with body: %s", flowId, obfuscate(bodyStr)));
		
		return performPOST(request, response, headers, bodyStr, envId, flowId);
	}

	@PostMapping(value = "/{envId}/flowExecutions/{flowExecutionId}", produces = "application/json;charset=UTF-8")
	public ResponseEntity<String> postExecution(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers, @RequestBody(required = true) String bodyStr,
			@PathVariable(value = "envId", required = true) String envId,
			@PathVariable(value = "flowExecutionId", required = true) String flowExecutionId) throws IOException, URISyntaxException, InterruptedException, EncryptionException, CustomAPIErrorException {

		if(log.isDebugEnabled())
			log.debug(String.format("Process postExecution - FlowId: %s, with body: %s", flowExecutionId, obfuscate(bodyStr)));
		
		return performPOST(request, response, headers, bodyStr, envId, flowExecutionId);
	}
	
	private ResponseEntity<String> performGET(HttpServletRequest request, HttpServletResponse response,
			MultiValueMap<String, String> headers,
			String envId) throws URISyntaxException, IOException, InterruptedException
	{
		
		Builder targetRequestBuilder = HttpRequest.newBuilder().uri(getTargetUrl(request)).GET();

		copyRequestHeaders(headers, request, targetRequestBuilder);

		HttpRequest targetRequest = targetRequestBuilder.build();
		
		HttpResponse<InputStream> targetResponse = executeTargetRequest(targetRequest, response);

		String responsePayload = getResponsePayload(targetResponse);

		return new ResponseEntity<String>(responsePayload,
				HttpStatus.valueOf(targetResponse.statusCode()));
	}
	
	private String getLocationHeader(HttpResponse<InputStream> targetResponse, HttpServletResponse response) throws IOException, InterruptedException
	{
		List<String> locationHeader = targetResponse.headers().map().get("location");
		
		if(locationHeader != null && locationHeader.size() == 1)
		{
			String location = locationHeader.get(0);				
			
			return location;
		}
		
		throw new InterruptedException("HTTP 302 Status found with no location header");
	}
	
	private ResponseEntity<String> performPOST(HttpServletRequest request, HttpServletResponse response,
			MultiValueMap<String, String> headers, String bodyStr,
			String envId,
			String flowId) throws EncryptionException, URISyntaxException, CustomAPIErrorException, IOException, InterruptedException
	{
		
		JSONObject retainedValues = updateRetainedValues(request, response, flowId, bodyStr);
		
		validateRequestPayload(retainedValues, bodyStr);
		
		Builder targetRequestBuilder = HttpRequest.newBuilder().uri(getTargetUrl(request)).POST(BodyPublishers.ofString(bodyStr));

		copyRequestHeaders(headers, request, targetRequestBuilder);

		HttpRequest targetRequest = targetRequestBuilder.build();
		
		HttpResponse<InputStream> targetResponse = executeTargetRequest(targetRequest, response);
		
		String responsePayload = getResponsePayload(targetResponse);
		
		return new ResponseEntity<String>(responsePayload,
				HttpStatus.valueOf(targetResponse.statusCode()));
	}

	private void validateRequestPayload(JSONObject retainedValues, String bodyStr) throws CustomAPIErrorException {

		JSONObject requestPayload = new JSONObject(bodyStr);
		JSONObject userRequestPayload = requestPayload.has("user")?requestPayload.getJSONObject("user"):requestPayload;
		
		boolean hasValidated = false;
		
		for(IValidator validator: this.registeredValidators.getRegisteredValidators())
		{
			if(!validator.isApplicable(userRequestPayload))
				continue;
			
			hasValidated = true;
			
			validator.validate(retainedValues, userRequestPayload);
		}
		
		if(hasValidated)
			this.enableUserMFA.enableMFA(retainedValues.getString("username"));
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
		JSONObject userRequestPayload = jsonPayload.has("user")?jsonPayload.getJSONObject("user"):jsonPayload;
		
		JSONObject cookieValues = getRetainedValuesFromCookie(flowId, request);
		
		for(String retainValue: this.retainValues)
		{
			if(!userRequestPayload.has(retainValue))
				continue;
			
			cookieValues.put(retainValue, userRequestPayload.get(retainValue));
		}
		
		String newEncryptedCookieValue = this.encryptionHelper.generate(flowId, cookieValues);
		
		addCookie(getCookieName(flowId), newEncryptedCookieValue, response);
		
		if(log.isDebugEnabled())
			log.debug("Retained Values: " + cookieValues.toString(4));
		
		return cookieValues;
	}
	
	private void addCookie(String cookieName, String cookieValue, HttpServletResponse response)
	{
		Cookie newCookie = new Cookie(cookieName, cookieValue);	
		newCookie.setPath("/");
		newCookie.setHttpOnly(true);
		newCookie.setSecure(true);
		response.addCookie(newCookie);
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
		if(request.getQueryString() != null && !request.getQueryString().trim().equals(""))
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

	private String getResponsePayload(HttpResponse<InputStream> response) throws UnsupportedOperationException, IOException {
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
			InputStream bodyInputStream = getDecodedInputStream(response);
			
		    String text = IOUtils.toString(bodyInputStream, StandardCharsets.UTF_8.name());

			if(log.isDebugEnabled())
				log.debug("Body: " + text);
			
			return text;
		}

	}
	
	private HttpResponse<InputStream> executeTargetRequest(HttpRequest targetRequest, HttpServletResponse response) throws IOException, InterruptedException {
		return executeTargetRequest(targetRequest, response, true);
	}

	private HttpResponse<InputStream> executeTargetRequest(HttpRequest targetRequest, HttpServletResponse response, boolean isSetResponseHeaders) throws IOException, InterruptedException {

		HttpResponse<InputStream> targetResponse = httpClient.send(targetRequest, BodyHandlers.ofInputStream());
		
		if(isSetResponseHeaders)
		{
			for(String headerName: targetResponse.headers().map().keySet())
			{				
				if(headerName.equalsIgnoreCase(":status") || headerName.equalsIgnoreCase("content-encoding") || headerName.equalsIgnoreCase("content-type") || headerName.equalsIgnoreCase("content-length") || headerName.toLowerCase().startsWith("access-control"))
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
	
	private static InputStream getDecodedInputStream(
	        HttpResponse<InputStream> httpResponse) {
	    String encoding = determineContentEncoding(httpResponse);
	    try {
	        switch (encoding) {
	            case "":
	                return httpResponse.body();
	            case "gzip":
	                return new GZIPInputStream(httpResponse.body());
	            default:
	                throw new UnsupportedOperationException(
	                        "Unexpected Content-Encoding: " + encoding);
	        }
	    } catch (IOException ioe) {
	        throw new UncheckedIOException(ioe);
	    }
	}

	private static String determineContentEncoding(
	        HttpResponse<?> httpResponse) {
	    return httpResponse.headers().firstValue("Content-Encoding").orElse("");
	}

}
