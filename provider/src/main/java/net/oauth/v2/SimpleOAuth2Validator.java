/*
 * Copyright 2010,2011,2012 Yutaka Obuchi
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Original is OAuth Java library(http://oauth.googlecode.com/svn/code/java/)
// and modified for OAuth 2.0 Provider

// Original's copyright and license terms
/*
 * Copyright 2008 Google, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.oauth.v2;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import net.oauth.v2.OAuth2Validator;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;

//TODO: move this class into oauth-provider
/**
 * A simple OAuthValidator, which checks the version, whether the timestamp is
 * close to now, the nonce hasn't been used before and the signature is valid.
 * Each check may be overridden.
 * <p>
 * This implementation is less than industrial strength:
 * <ul>
 * <li>Duplicate nonces won't be reliably detected by a service provider running
 * in multiple processes, since the used nonces are stored in memory.</li>
 * <li>The collection of used nonces is a synchronized choke point</li>
 * <li>The used nonces may occupy lots of memory, although you can minimize this
 * by calling releaseGarbage periodically.</li>
 * <li>The range of acceptable timestamps can't be changed, and there's no
 * system for increasing the range smoothly.</li>
 * <li>Correcting the clock backward may allow duplicate nonces.</li>
 * </ul>
 * For a big service provider, it might be better to store used nonces in a
 * database.
 * 
 * @author Dirk Balfanz
 * @author John Kristian
 */
public class SimpleOAuth2Validator implements OAuth2Validator {

    /** The default maximum age of timestamps is 5 minutes. */
    public static final long DEFAULT_MAX_TIMESTAMP_AGE = 5 * 60 * 1000L;
    public static final long DEFAULT_TIMESTAMP_WINDOW = DEFAULT_MAX_TIMESTAMP_AGE;

    /**
     * Names of parameters that may not appear twice in a valid message.
     * This limitation is specified by OAuth Core <a
     * href="http://oauth.net/core/1.0#anchor7">section 5</a>.
     */
    //public static final Set<String> SINGLE_PARAMETERS = constructSingleParameters();

    //private static Set<String> constructSingleParameters() {
    //    Set<String> s = new HashSet<String>();
     //   for (String p : new String[] { OAuth.OAUTH_CONSUMER_KEY, OAuth.OAUTH_TOKEN, OAuth.OAUTH_TOKEN_SECRET,
     //           OAuth.OAUTH_CALLBACK, OAuth.OAUTH_SIGNATURE_METHOD, OAuth.OAUTH_SIGNATURE, OAuth.OAUTH_TIMESTAMP,
     //           OAuth.OAUTH_NONCE, OAuth.OAUTH_VERSION }) {
     //       s.add(p);
     //   }
    //    return Collections.unmodifiableSet(s);
    //}

    /**
     * Construct a validator that rejects messages more than five minutes old or
     * with a OAuth version other than 1.0.
     */
    public SimpleOAuth2Validator() {
        this(DEFAULT_TIMESTAMP_WINDOW, Double.parseDouble(OAuth2.VERSION_2_0));
    }

    /**
     * Public constructor.
     * 
     * @param maxTimestampAgeMsec
     *            the range of valid timestamps, in milliseconds into the past
     *            or future. So the total range of valid timestamps is twice
     *            this value, rounded to the nearest second.
     * @param maxVersion
     *            the maximum valid oauth_version
     */
    public SimpleOAuth2Validator(long maxTimestampAgeMsec, double maxVersion) {
        this.maxTimestampAgeMsec = maxTimestampAgeMsec;
        this.maxVersion = maxVersion;
    }

    protected final double minVersion = 1.0;
    protected final double maxVersion;
    protected final long maxTimestampAgeMsec;


    /** {@inherit} 
     * @throws URISyntaxException */
    public void validateMessage(OAuth2Message message, OAuth2Accessor accessor)
    throws OAuth2Exception, IOException, URISyntaxException {

    }

    
    /** {@inherit} 
     * @throws URISyntaxException */
    public void validateRequestMessageForAuthorization(OAuth2Message message,OAuth2Client client)
    throws OAuth2Exception, IOException, URISyntaxException {
        //checkSingleParameters(message);
        validateResponseType(message);
        validateRedirectUri(message,client);
    }
    
    /** {@inherit} 
     * @throws URISyntaxException */
    public void validateRequestMessageForAccessToken(OAuth2Message message, OAuth2Accessor accessor)
    throws OAuth2Exception, IOException, URISyntaxException {

        String grant_type = message.getParameter(OAuth2.GRANT_TYPE);

        //checkSingleParameters(message);
        String authz = message.getHeader("Authorization");
        if (authz != null) {
            validateBasicAuthentication(message, accessor);
        } else {
            validateClientIdWithPassword(message, accessor);
        }
        if(!grant_type.equals(OAuth2.GrantType.CLIENT_CREDENTIALS)){
            validateRedirectUri(message, accessor.client);
        }

        validateScope(message,accessor);

    }
    
    /** Throw an exception if any SINGLE_PARAMETERS occur repeatedly. */
    //protected void checkSingleParameters(OAuth2Message message) throws IOException, OAuth2Exception {
    //    // Check for repeated oauth_ parameters:
    //    boolean repeated = false;
    //    Map<String, Collection<String>> nameToValues = new HashMap<String, Collection<String>>();
    //    for (Map.Entry<String, String> parameter : message.getParameters()) {
    //        String name = parameter.getKey();
    //        if (SINGLE_PARAMETERS.contains(name)) {
    //            Collection<String> values = nameToValues.get(name);
    //            if (values == null) {
    //                values = new ArrayList<String>();
    //                nameToValues.put(name, values);
    //            } else {
    //                repeated = true;
    //            }
    //            values.add(parameter.getValue());
    //        }
    //    }
    //    if (repeated) {
    //        Collection<OAuth2.Parameter> rejected = new ArrayList<OAuth2.Parameter>();
    //        for (Map.Entry<String, Collection<String>> p : nameToValues.entrySet()) {
    //            String name = p.getKey();
    //            Collection<String> values = p.getValue();
    //            if (values.size() > 1) {
    //                for (String value : values) {
    //                    rejected.add(new OAuth2.Parameter(name, value));
    //                }
    //            }
    //        }
    //        OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.Problems.PARAMETER_REJECTED);
    //        problem.setParameter(OAuth2.Problems.OAUTH_PARAMETERS_REJECTED, OAuth2.formEncode(rejected));
    //        throw problem;
    //    }
    //}


    /**
     * Throw an exception if Basic Authentication has been validated.
     *
     */
    protected void validateBasicAuthentication(OAuth2Message message, OAuth2Accessor accessor)
    throws IOException,OAuth2Exception {
        String authz = message.getHeader("Authorization");
        if (authz != null) {
            if(authz.substring(0,5).equals("Basic")){
                String userPass = new String(Base64.decodeBase64(authz.substring(6).getBytes()), "UTF-8");

                int loc = userPass.indexOf(":");
                if (loc == -1) {
                    OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_CLIENT);
                    throw problem;
                }

                String userPassedIn = userPass.substring(0, loc);
                String user = userPassedIn;
                String pass = userPass.substring(loc + 1);
                if(user!=null && pass!=null){
                    if (!user.equals(accessor.client.clientId)) {
                        OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_CLIENT);
                        throw problem;
                    }else{
                        if(!pass.equals(accessor.client.clientSecret)){
                            OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_CLIENT);
                            throw problem;
                        }

                        return;
                    }
                }

            }
        }
    }

    protected void validateClientIdWithPassword(OAuth2Message message, OAuth2Accessor accessor)
    throws OAuth2Exception, IOException {
        String client_id = message.getParameter(OAuth2.CLIENT_ID);
        if (client_id != null) {
            if (!client_id.equals(accessor.client.clientId)) {
                OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_CLIENT);
                throw problem;
            }else{
            	/* credential check. Spec(draft-ietf-oauth-v2-10) says wa have to chchek Authorization parameter 
            	 * with Basic Authentication and client_secret parameter.*/
            	if(message.getParameter(OAuth2.CLIENT_SECRET) != null){
            		if(!message.getParameter(OAuth2.CLIENT_SECRET).equals(accessor.client.clientSecret)){
            			OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_CLIENT);
                        throw problem;	
            		}
            		
            		return;
            	}else{
            		OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_REQUEST);
            		throw problem;
            	}
            }
            
        } else{
        	OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_REQUEST);
        	throw problem;
        }
    }

    protected void validateRedirectUri(OAuth2Message message, OAuth2Client client)
    throws OAuth2Exception, IOException {
        String redirect_uri = message.getParameter(OAuth2.REDIRECT_URI);
        if (redirect_uri != null) {
            if (!OAuth2.decodePercent(redirect_uri).equals(client.redirectUri)) {
                OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_REQUEST);
                throw problem;
            }
        }
    }

    /*
     * make sure if scope is valid or not. In this simple validater, just check if valid is equal.
     */
    protected void validateScope(OAuth2Message message, OAuth2Accessor accessor)
            throws OAuth2Exception, IOException {
        String scope = message.getParameter(OAuth2.SCOPE);
        if (scope != null) {
            if(!scope.equals(accessor.scope)){
                OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_SCOPE);
                throw problem;
            }
        } else if (accessor.scope != null){
            OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_SCOPE);
            throw problem;
        }
    }

    /*
     * check if response type is the one of them which are defiend in sped
     */
    protected void validateResponseType(OAuth2Message message)
    throws OAuth2Exception, IOException {
        String response_type = message.getParameter(OAuth2.RESPONSE_TYPE);
        if (response_type != null) {
            if (!( response_type.equals(OAuth2.ResponseType.CODE)||
                    response_type.equals(OAuth2.ResponseType.TOKEN)||
                    response_type.equals(OAuth2.ResponseType.CODE_AND_TOKEN))) {
                OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.UNSUPPORTED_RESPONSE_TYPE);
                throw problem;
            }
        } else{
        	OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_REQUEST);
        	throw problem;
        	
        }
        
    }


    /** Get the number of milliseconds since midnight, January 1, 1970 UTC. */
    protected long currentTimeMsec() {
        return System.currentTimeMillis();
    }

}
