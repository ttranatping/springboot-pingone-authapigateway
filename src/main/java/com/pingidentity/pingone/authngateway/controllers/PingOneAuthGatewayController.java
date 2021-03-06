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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.json.JSONException;
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
import com.pingidentity.pingone.authngateway.helpers.EncryptionHelper;
import com.pingidentity.pingone.authngateway.helpers.PingOneUserHelper;
import com.pingidentity.pingone.authngateway.validators.IValidator;
import com.pingidentity.pingone.authngateway.validators.ValidatorRegister;

@Controller
@RequestMapping("/")
public class PingOneAuthGatewayController {
	
	private static final Logger log = LoggerFactory.getLogger(PingOneAuthGatewayController.class);
	private static final String EmailAttribute = "username";

	@Autowired
	private ValidatorRegister registeredValidators;

	@Value("${ping.authHost}")
	private String authHost;

	@Value("${ping.mfa.attributeName}")
	private String mfaAttributeName;
	
	@Value("${ping.retainValues.claims}")
	private String[] retainValues;
	
	@Value("${ping.retainValues.key}")
	private String[] retainValueKeys;
	
	@Value("${ping.obfuscateValues}")
	private String[] obfuscateValues;
	
	@Autowired
	private EncryptionHelper encryptionHelper;

	private HttpClient httpClient = null;
	
	@Autowired
	private PingOneUserHelper p1UserHelper;

	@PostConstruct
	public void init() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, EncryptionException, ClassNotFoundException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException, URISyntaxException {
		
		httpClient = HttpClient.newBuilder()
			      .version(HttpClient.Version.HTTP_2)
			      .followRedirects(HttpClient.Redirect.NEVER)
			      .build();
		
	}

	@GetMapping("/as/authorize")
	public void authorize(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers) throws IOException, InterruptedException, URISyntaxException {

		if(log.isDebugEnabled())
			log.debug("Process Authorize Endpoint");
		
		Builder targetRequestBuilder = HttpRequest.newBuilder().uri(getTargetUrl(request)).GET();

		copyRequestHeaders(headers, request, targetRequestBuilder);

		HttpRequest targetRequest = targetRequestBuilder.build();
		
		HttpResponse<InputStream> targetResponse = executeTargetRequest(targetRequest, response, true, true);

		String location = getLocationHeader(targetResponse, response);

		if(log.isDebugEnabled())
			log.debug("Location header: " + location);
		
		response.sendRedirect(location);
		response.setStatus(302);
		response.addHeader(":status", "302");
	}

	@GetMapping(value = "/experiences/{experienceId}", produces = "text/html;charset=UTF-8")
	public ResponseEntity<String> getExperiences(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers,
			@RequestParam String redirectUri) throws IOException, InterruptedException, URISyntaxException, EncryptionException {

		String flowId = redirectUri.substring(redirectUri.indexOf("/flows/") + "/flows/".length()).replace("flowExecutionCallback", "").replaceAll("\\/", "");

		if(log.isDebugEnabled())
			log.debug("Process getExperiences flowId: " + flowId);
		
		return performGET(request, response, headers, null, true);
	}

	@GetMapping(value = "/flows/{flowId}/flowExecutionCallback", produces = "text/html;charset=UTF-8")
	public ResponseEntity<String> getFlowExecutionCallback(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers,
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
		
		return performGET(request, response, headers, null, true);
	}

	@GetMapping(value = "/flows/{flowId}", produces = "application/hal+json;charset=UTF-8")
	public ResponseEntity<String> get(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers,
			@PathVariable(value = "flowId", required = true) String flowId) throws IOException, InterruptedException, URISyntaxException, EncryptionException {

		if(log.isDebugEnabled())
			log.debug("Process GET flows");
		
		return performGET(request, response, headers, flowId, true);
	}

	@GetMapping(value = {"/**"})
	public ResponseEntity<String> getAll(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers) throws IOException, InterruptedException, URISyntaxException, EncryptionException {

		if(log.isDebugEnabled())
			log.debug("Process GET all");
		
		return performGET(request, response, headers, null, false);
	}

	@GetMapping(value = {"/**/*.otf", "/**/*.woff2", "/**/*.ttf", "/**/*.woff"}, produces="binary/octet-stream;")
	public ResponseEntity<String> getOctetStream(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers) throws IOException, InterruptedException, URISyntaxException, EncryptionException {

		if(log.isDebugEnabled())
			log.debug("Process GET octet stream");
		
		return performGET(request, response, headers, null, false);
	}

	@GetMapping(value = {"/**/*.png"}, produces="image/png")
	public ResponseEntity<String> getPNG(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers) throws IOException, InterruptedException, URISyntaxException, EncryptionException {

		if(log.isDebugEnabled())
			log.debug("Process GET png");
		
		return performGET(request, response, headers, null, false);
	}

	@GetMapping(value = {"/**/*.js"}, produces="application/javascript;charset=UTF-8")
	public ResponseEntity<String> getJavascript(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers) throws IOException, InterruptedException, URISyntaxException, EncryptionException {

		if(log.isDebugEnabled())
			log.debug("Process GET javascript");
		
		return performGET(request, response, headers, null, false);
	}

	@GetMapping(value = {"/**/*.json"}, produces="application/json;charset=UTF-8")
	public ResponseEntity<String> getJson(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers) throws IOException, InterruptedException, URISyntaxException, EncryptionException {

		if(log.isDebugEnabled())
			log.debug("Process GET json");
		
		return performGET(request, response, headers, null, false);
	}

	@GetMapping(value = {"/**/*.css"}, produces="text/css;charset=UTF-8")
	public ResponseEntity<String> getCSS(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers) throws IOException, InterruptedException, URISyntaxException, EncryptionException {

		if(log.isDebugEnabled())
			log.debug("Process GET CSS");
		
		return performGET(request, response, headers, null, false);
	}

	@PostMapping(value = "/flows/{flowId}", produces = "application/hal+json;charset=UTF-8")
	public ResponseEntity<String> post(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers, @RequestBody(required = true) String bodyStr,
			@PathVariable(value = "flowId", required = true) String flowId) throws IOException, URISyntaxException, InterruptedException, EncryptionException, CustomAPIErrorException {

		if(log.isDebugEnabled())
			log.debug(String.format("Process POST - FlowId: %s", flowId));
		
		if(log.isDebugEnabled())
			log.debug(String.format("Process POST - FlowId: %s", flowId));
		
		return performPOST(request, response, headers, bodyStr, flowId);
	}

	@PostMapping(value = "/as/**", produces = "application/json;charset=UTF-8")
	public ResponseEntity<String> postAS(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers, @RequestBody(required = true) String bodyStr) throws IOException, URISyntaxException, InterruptedException, EncryptionException, CustomAPIErrorException {

		Builder targetRequestBuilder = HttpRequest.newBuilder().uri(getTargetUrl(request)).POST(BodyPublishers.ofString(bodyStr));

		copyRequestHeaders(headers, request, targetRequestBuilder);

		HttpRequest targetRequest = targetRequestBuilder.build();
		
		HttpResponse<InputStream> targetResponse = executeTargetRequest(targetRequest, response, true);
		
		String responsePayload = getResponsePayload(targetResponse);
		
		return new ResponseEntity<String>(responsePayload,
				HttpStatus.valueOf(targetResponse.statusCode()));
	}

	@PostMapping(value = "/flowExecutions/{flowExecutionId}", produces = "application/json;charset=UTF-8")
	public ResponseEntity<String> postExecution(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers, @RequestBody(required = true) String bodyStr,
			@PathVariable(value = "flowExecutionId", required = true) String flowExecutionId) throws IOException, URISyntaxException, InterruptedException, EncryptionException, CustomAPIErrorException {

		if(log.isDebugEnabled())
			log.debug(String.format("Process postExecution - FlowId: %s", flowExecutionId));
		
		return performPOST(request, response, headers, bodyStr, flowExecutionId);
	}
	
	private ResponseEntity<String> performGET(HttpServletRequest request, HttpServletResponse response,
			MultiValueMap<String, String> headers,
			String flowId, boolean ignoreContentType) throws URISyntaxException, IOException, InterruptedException, EncryptionException
	{
		JSONObject retainedValues = this.updateRetainedValuesRequest(request, response, flowId, null);
		
		Builder targetRequestBuilder = HttpRequest.newBuilder().uri(getTargetUrl(request)).GET();

		copyRequestHeaders(headers, request, targetRequestBuilder);

		HttpRequest targetRequest = targetRequestBuilder.build();
		
		HttpResponse<InputStream> targetResponse = executeTargetRequest(targetRequest, response, true, ignoreContentType);

		String responsePayload = getResponsePayload(targetResponse);
		
		this.updateRetainedValuesResponse(response, responsePayload, flowId, retainedValues);

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
			String flowId) throws EncryptionException, URISyntaxException, CustomAPIErrorException, IOException, InterruptedException
	{
		
		JSONObject retainedValues = this.updateRetainedValuesRequest(request, response, flowId, bodyStr);
		
		boolean hasValidated = validateRequestPayload(retainedValues, bodyStr);
		
		this.registerMFARequest(hasValidated, retainedValues);
		
		Builder targetRequestBuilder = HttpRequest.newBuilder().uri(getTargetUrl(request)).POST(BodyPublishers.ofString(bodyStr));

		copyRequestHeaders(headers, request, targetRequestBuilder);

		HttpRequest targetRequest = targetRequestBuilder.build();
		
		HttpResponse<InputStream> targetResponse = executeTargetRequest(targetRequest, response, true);
		
		String responsePayload = getResponsePayload(targetResponse);
		
		this.updateRetainedValuesResponse(response, responsePayload, flowId, retainedValues);
		
		this.registerMFAResponse(targetResponse.statusCode(), hasValidated, retainedValues);
		
		return new ResponseEntity<String>(responsePayload,
				HttpStatus.valueOf(targetResponse.statusCode()));
	}

	//determines whether we need to register email MFA after request validation and before request submission
	//enabling mfa prior to the request submission will result in the user having to perform MFA
	//however this might not be ideal e.g. if the user has already verified the same email address during registration
	private void registerMFARequest(boolean hasValidated, JSONObject retainedValues) throws JSONException, CustomAPIErrorException {
		
		if(!hasValidated)
			return;
		
		if(EmailAttribute.equals(mfaAttributeName))
		{
			if(log.isDebugEnabled())
				log.debug("Not enabling MFA device because email attribute name is the same as mfa attribute. User has already verified their email.");
			return;
		}
		
		if(!retainedValues.has(EmailAttribute))
		{
			if(log.isDebugEnabled())
				log.debug("Not enabling MFA device because retained attributes does not contain EmailAttribute.");
			return;
		}
		
		if(!retainedValues.has(mfaAttributeName))
		{
			if(log.isDebugEnabled())
				log.debug("Not enabling MFA device because retained attributes does not contain mfaAttributeName.");
			return;
		}
		
		String emailAttribute = retainedValues.getString(EmailAttribute);
		String mfaAttribute = retainedValues.getString(mfaAttributeName);
		
		if(emailAttribute.equalsIgnoreCase(mfaAttribute))
		{
			if(log.isDebugEnabled())
				log.debug("Not enabling MFA device because email attribute value is equal to mfa attribute value. User has already verified their email.");
			
			return;
		}
		
		this.p1UserHelper.registerEmailDevice(retainedValues.getString("username"), mfaAttribute);
		
	}
	
	private void registerMFAResponse(int statusCode, boolean hasValidated, JSONObject retainedValues) throws JSONException, CustomAPIErrorException {
		
		if(!hasValidated)
			return;
		
		if(statusCode != 200)
			return;
		
		boolean isRegisterEmailDevice = false;
		String mfaAttribute = null;
		
		if(EmailAttribute.equals(mfaAttributeName))
		{
			if(log.isDebugEnabled())
				log.debug("Registering email after validation because MFA attribute is the same as Email.");
			
			isRegisterEmailDevice = true;
		}
		else if(retainedValues.has(EmailAttribute) && retainedValues.has(mfaAttributeName))
		{
			String emailAttribute = retainedValues.getString(EmailAttribute);
			mfaAttribute = retainedValues.getString(mfaAttributeName);
			
			if(emailAttribute.equalsIgnoreCase(mfaAttribute))
			{
				if(log.isDebugEnabled())
					log.debug("Registering email after validation because MFA email value is the same as Email.");
				
				isRegisterEmailDevice = true;
			}
		}
		else if(retainedValues.has(EmailAttribute))
		{
			if(log.isDebugEnabled())
				log.debug("Registering email after validation because MFA email not provided is the same as Email.");
			
			isRegisterEmailDevice = true;
			mfaAttribute = retainedValues.getString(EmailAttribute);
		}
		else if(retainedValues.has(mfaAttributeName))
		{
			if(log.isDebugEnabled())
				log.debug("Registering email after validation because email not provided but MFA email is.");
			
			isRegisterEmailDevice = true;
			mfaAttribute = retainedValues.getString(mfaAttributeName);
		}
			
		
		if(isRegisterEmailDevice)
			this.p1UserHelper.registerEmailDevice(retainedValues.getString("username"), mfaAttribute);
			
		
	}

	private boolean validateRequestPayload(JSONObject retainedValues, String bodyStr) throws CustomAPIErrorException {

		JSONObject requestPayload = new JSONObject(bodyStr);
		JSONObject userRequestPayload = requestPayload.has("user")?requestPayload.getJSONObject("user"):requestPayload;

		Map<String, Object> userRequestPayloadMap = convertJSONToUnmodifiableMap(userRequestPayload);
		Map<String, Object> retainedValuesMap = convertJSONToUnmodifiableMap(retainedValues);
		
		boolean hasValidated = false;
		
		for(IValidator validator: this.registeredValidators.getRegisteredValidators())
		{
			if(!validator.isApplicable(userRequestPayloadMap))
				continue;
			
			hasValidated = true;
			
			validator.validate(retainedValuesMap, userRequestPayloadMap);
		}
		
		if(hasValidated)
			this.p1UserHelper.enableMFA(retainedValues.getString("username"), "username");
		
		return hasValidated;
	}

	private Map<String, Object> convertJSONToUnmodifiableMap(JSONObject userRequestPayload) {
		Map<String, Object> map = new HashMap<String, Object>();
		
		for(String key: userRequestPayload.keySet())
			map.put(key, userRequestPayload.get(key));
		
		return Collections.unmodifiableMap(map);
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

	private JSONObject updateRetainedValuesRequest(HttpServletRequest request, HttpServletResponse response, String flowId, String bodyStr) throws EncryptionException {
		if(flowId == null)
			return null;
		
		JSONObject cookieValues = getRetainedValuesFromCookie(flowId, request);
		
		if(bodyStr == null)
			return cookieValues;
		
		JSONObject jsonPayload = new JSONObject(bodyStr);
		JSONObject userRequestPayload = jsonPayload.has("user")?jsonPayload.getJSONObject("user"):jsonPayload;
		
		for(String retainValue: this.retainValues)
		{
			if(!userRequestPayload.has(retainValue))
				continue;
			
			cookieValues.put(retainValue, userRequestPayload.get(retainValue));
		}
		
		if(log.isDebugEnabled())
			log.debug("Retained Values Request: " + cookieValues.toString(4));
		
		return cookieValues;
	}

	private JSONObject updateRetainedValuesResponse(HttpServletResponse response, String payload, String flowId, JSONObject retainAttributes) throws EncryptionException {
		if(flowId == null)
			return null;
		
		JSONObject jsonPayload = new JSONObject(payload);
		JSONObject formDataPayload = jsonPayload.has("formData")?jsonPayload.getJSONObject("formData"):jsonPayload;
		JSONObject userRequestPayload = formDataPayload.has("user")?formDataPayload.getJSONObject("user"):formDataPayload;
		
		for(String retainValue: this.retainValues)
		{
			if(!userRequestPayload.has(retainValue))
				continue;
			
			retainAttributes.put(retainValue, userRequestPayload.get(retainValue));
		}
		
		if(!retainAttributes.has("username"))
		{
			for(String retainValueKey : this.retainValueKeys)
			{
				if(retainValueKey.equals("username"))
					continue;
				
				if(!retainAttributes.has(retainValueKey))
					continue;
				
				try {
					String username = this.p1UserHelper.getUserName(String.valueOf(retainAttributes.get(retainValueKey)), retainValueKey);
					retainAttributes.put("username", username);
					
				} catch (JSONException | CustomAPIErrorException e) {
					continue;
				}
			}
		}
		
		String newEncryptedCookieValue = this.encryptionHelper.generate(flowId, retainAttributes);
		
		addCookie(getCookieName(flowId), newEncryptedCookieValue, response);
		
		if(log.isDebugEnabled())
			log.debug("Retained Values Response: " + retainAttributes.toString(4));
		
		return retainAttributes;
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

			if(log.isTraceEnabled())
				log.trace("Body: " + text);
			
			return text;
		}

	}
	
	private HttpResponse<InputStream> executeTargetRequest(HttpRequest targetRequest, HttpServletResponse response, boolean ignoreContentType) throws IOException, InterruptedException {
		return executeTargetRequest(targetRequest, response, true, ignoreContentType);
	}

	private HttpResponse<InputStream> executeTargetRequest(HttpRequest targetRequest, HttpServletResponse response, boolean isSetResponseHeaders, boolean ignoreContentType) throws IOException, InterruptedException {

		HttpResponse<InputStream> targetResponse = httpClient.send(targetRequest, BodyHandlers.ofInputStream());
		
		if(log.isDebugEnabled())
			log.debug("target content-type is: " + targetResponse.headers().firstValue("Content-Type"));
		
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
