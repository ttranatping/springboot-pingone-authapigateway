package com.pingidentity.pingone.authngateway.controllers;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.json.JSONObject;

import com.pingidentity.pingone.authngateway.exceptions.EncryptionException;

public class EncryptionHelper {

	private JsonWebKey jsonWebKey = null;
	private final String encryptionJWK, issuer;
	private final String[] retainAttributeList;
	
	private final JwtConsumer jwtConsumer;
	
	public EncryptionHelper(String encryptionJWK, String issuer, String[] retainAttributeList) throws EncryptionException
	{
		this.encryptionJWK = encryptionJWK;
		this.issuer = issuer;
		this.retainAttributeList = retainAttributeList;
		
		try {
			jwtConsumer = generateNewConsumer();
		} catch (JoseException e) {
			throw new EncryptionException("Unable to generate Jwt Consumer", e);
		}

		try {
			jsonWebKey = JsonWebKey.Factory.newJwk(this.encryptionJWK);
		} catch (JoseException e) {
			throw new EncryptionException("Unable to generate new JWK WebKey", e);
		}
	}

	public String generate(String flowId, JSONObject requestPayload) throws EncryptionException {

		JwtClaims claims = new JwtClaims();

		for (String requestClaim : this.retainAttributeList) {
			if (requestPayload.has(requestClaim)) {
				claims.setClaim(requestClaim, requestPayload.get(requestClaim));
			}
		}

		claims.setIssuer(this.issuer);
		claims.setIssuedAtToNow();
		claims.setSubject(flowId);

		JsonWebEncryption jwe = new JsonWebEncryption();

		jwe.setPayload(claims.toJson());
		jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
		jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
		jwe.setKey(jsonWebKey.getKey());

		String jwt;
		try {
			jwt = jwe.getCompactSerialization();
		} catch (JoseException e) {
			throw new EncryptionException("Unable to encrypt JWT", e);
		}

		return jwt;
	}
	
	public JSONObject read(String flowId, String encryptedJwt) throws EncryptionException
	{
		JwtClaims claims;
		try {
			claims = getJWTClaims(encryptedJwt);
		} catch (JoseException | InvalidJwtException e) {
			throw new EncryptionException("Unable to read encrypted JWT", e);
		}
		
		try {
			if(!claims.getSubject().equals(flowId))
				throw new EncryptionException("FlowId does not match encrypted subject");
		} catch (MalformedClaimException e) {
			throw new EncryptionException("Malformed FlowId does not match encrypted subject", e);
		}
		
		JSONObject returnObject = new JSONObject();
		
		for(String claimName: claims.getClaimNames())
			returnObject.put(claimName, claims.getClaimValueAsString(claimName));
		
		return returnObject;
	}

	private JwtConsumer generateNewConsumer() throws JoseException {

		if (jsonWebKey == null)
			jsonWebKey = JsonWebKey.Factory.newJwk(this.encryptionJWK);

		JwtConsumer jwtConsumer = new JwtConsumerBuilder()								// time
				.setRequireSubject() // the JWT must have a subject claim
				.setExpectedIssuer(this.issuer) // whom the JWT needs to have been issued by
				.setDecryptionKey(jsonWebKey.getKey()) // verify the signature with the public key
				.setDisableRequireSignature().build();

		return jwtConsumer;
	}

	private JwtClaims getJWTClaims(String encryptedJwt) throws JoseException, InvalidJwtException {

		JwtClaims jwtClaims = jwtConsumer.processToClaims(encryptedJwt);

		return jwtClaims;
	}
	
}
