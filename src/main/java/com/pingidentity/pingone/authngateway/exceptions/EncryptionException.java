package com.pingidentity.pingone.authngateway.exceptions;

public class EncryptionException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public EncryptionException(String message, Throwable t)
	{
		super(message, t);
	}

	public EncryptionException(String message) {
		super(message);
	}

}
