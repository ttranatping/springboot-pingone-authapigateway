package com.pingidentity.pingone.authngateway.exceptions;

public class CustomAPIErrorException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private final String target, code, message, detailedCode, detailedMessage;

	public CustomAPIErrorException(String target, String code, String message, String detailedCode, String detailedMessage)
	{
		this.target = target;
		this.code = code;
		this.message = message;
		this.detailedMessage = detailedMessage;
		this.detailedCode = detailedCode;
	}
	
	public String getTarget() {
		return target;
	}

	public String getCode() {
		return code;
	}

	public String getMessage() {
		return message;
	}

	public String getDetailedCode() {
		return detailedCode;
	}

	public String getDetailedMessage() {
		return detailedMessage;
	}

}
