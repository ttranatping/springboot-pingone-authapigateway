package com.pingidentity.pingone.authngateway.config;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.GenericFilterBean;

public class AddSameSiteCookie extends GenericFilterBean {

	//@TODO make this configurable
	private static final String SAMESITE_VALUE="none";
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		addSameSiteCookieAttribute(response);
		
		chain.doFilter(request, response);

	}

    private void addSameSiteCookieAttribute(ServletResponse servletResponse) {
    	
    	if(!(servletResponse instanceof HttpServletResponse))
    		return;
    	
    	HttpServletResponse response = (HttpServletResponse)servletResponse;
    	
        Collection<String> headers = response.getHeaders(HttpHeaders.SET_COOKIE);
        boolean firstHeader = true;
        for (String header : headers) { // there can be multiple Set-Cookie attributes
            if (firstHeader) {
                response.setHeader(HttpHeaders.SET_COOKIE, String.format("%s; %s", header, "SameSite=" + SAMESITE_VALUE));
                firstHeader = false;
                continue;
            }
            response.addHeader(HttpHeaders.SET_COOKIE, String.format("%s; %s", header, "SameSite=" + SAMESITE_VALUE));
        }
    }

}
