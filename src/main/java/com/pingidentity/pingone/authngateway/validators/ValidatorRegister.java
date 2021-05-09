package com.pingidentity.pingone.authngateway.validators;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class ValidatorRegister {
	
	private static Logger log = LoggerFactory.getLogger(ValidatorRegister.class);

	private final List<IValidator> registeredValidators = new ArrayList<IValidator>();
	
	public void register(IValidator validator)
	{
		if(log.isDebugEnabled())
			log.debug("Registering validator: " + validator.info());
		
		this.registeredValidators.add(validator);
	}
	
	public List<IValidator> getRegisteredValidators()
	{
		return this.registeredValidators;
	}
}
