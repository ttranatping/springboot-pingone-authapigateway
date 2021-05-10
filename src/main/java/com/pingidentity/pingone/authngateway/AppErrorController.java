package com.pingidentity.pingone.authngateway;

import java.util.UUID;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.pingidentity.pingone.authngateway.exceptions.CustomAPIErrorException;

@ControllerAdvice
public class AppErrorController {

	private static final String errorTemplate = "	{\n" + "	   \"id\" : \"%s\",\n" + "	   \"code\" : \"%s\",\n"
			+ "	   \"message\" : \"%s\",\n" + "	   \"details\" : [ {\n" + "	     \"code\" : \"%s\",\n"
			+ "	     \"target\" : \"%s\",\n" + "	     \"message\" : \"%s\"\n" + "	   } ]\n" + "	 }";

	@ExceptionHandler(value = { CustomAPIErrorException.class })
	public ResponseEntity<String> multipleHandler(final CustomAPIErrorException e) {

		HttpHeaders headers = new HttpHeaders();
		headers.set("Content-Type", "application/hal+json;charset=UTF-8");

		String id = UUID.randomUUID().toString();
		String code = e.getCode();
		String message = e.getMessage();
		String detailedCode = e.getDetailedCode();
		String detailedTarget = e.getTarget();
		String detailedMessage = e.getDetailedMessage();

		String responsePayload = String.format(errorTemplate, id, code, message, detailedCode, detailedTarget,
				detailedMessage);

		return new ResponseEntity<String>(responsePayload, headers, HttpStatus.BAD_REQUEST);
	}

}