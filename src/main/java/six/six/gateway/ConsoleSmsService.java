package six.six.gateway;

import org.jboss.logging.Logger;

/*
 * Ashok Kumar <ashok@parserlabs.com>
 * Note: Just for debugging purpose. Not to be used in Production.
 */

public class ConsoleSmsService implements SMSService{
	
	private static Logger logger = Logger.getLogger(ConsoleSmsService.class);
	
	@Override
	public boolean send(String phoneNumber, String message, String login, String pw) {
		logger.warn("Sending msg to " + phoneNumber +"");
		logger.warn(message);
		return true;
	}

}
