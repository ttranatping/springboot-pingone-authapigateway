package com.pingidentity.pingone.authngateway.controllers;

import java.io.IOException;
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
import java.util.List;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping("/")
public class PingOneAuthGatewayController {
	
	private static Logger log = LoggerFactory.getLogger(PingOneAuthGatewayController.class);

	@Value("${ping.authHost}")
	private String authHost;

	private HttpClient httpClient = null;

	@PostConstruct
	public void init() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
		
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

	@PostMapping(value = "/{envId}/**", produces = "application/hal+json;charset=UTF-8")
	public ResponseEntity<String> post(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers, @RequestBody(required = true) String bodyStr,
			@PathVariable(value = "envId", required = true) String envId) throws IOException, URISyntaxException, InterruptedException {

		if(log.isDebugEnabled())
			log.debug("Process POST");
		
		Builder targetRequestBuilder = HttpRequest.newBuilder().uri(getTargetUrl(request)).POST(BodyPublishers.ofString(bodyStr));

		copyRequestHeaders(headers, request, targetRequestBuilder);

		HttpRequest targetRequest = targetRequestBuilder.build();
		
		HttpResponse<String> targetResponse = executeTargetRequest(targetRequest, response);
		
		String responsePayload = getResponsePayload(targetResponse);

		return new ResponseEntity<String>(responsePayload,
				HttpStatus.valueOf(targetResponse.statusCode()));
	}

	@RequestMapping(method = RequestMethod.OPTIONS, value = "/{envId}/**")
	public ResponseEntity<String> options(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader MultiValueMap<String, String> headers,
			@PathVariable(value = "envId", required = true) String envId) throws URISyntaxException, IOException, InterruptedException {
		

		if(log.isDebugEnabled())
			log.debug("Process OPTIONS");
		
		Builder targetRequestBuilder = HttpRequest.newBuilder().uri(getTargetUrl(request));

		targetRequestBuilder.method("OPTIONS", BodyPublishers.noBody());
		
		copyRequestHeaders(headers, request, targetRequestBuilder);

		HttpRequest targetRequest = targetRequestBuilder.build();
		
		HttpResponse<String> targetResponse = executeTargetRequest(targetRequest, response);

		String responsePayload = getResponsePayload(targetResponse);

		return new ResponseEntity<String>(responsePayload,
				HttpStatus.valueOf(targetResponse.statusCode()));
	}

	private URI getTargetUrl(HttpServletRequest request) throws URISyntaxException {
		String url = null;
		if(!StringUtils.isEmpty(request.getQueryString()))
			url = String.format("https://%s%s?%s", this.authHost, request.getRequestURI(), request.getQueryString());
		else
			url = String.format("https://%s%s", this.authHost, request.getRequestURI());
		
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
