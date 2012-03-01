/*
 * Copyright 2010 Yutaka Obuchi
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
//import net.oauth.signature.OAuthSignatureMethod;
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
    //private final Set<UsedNonce> usedNonces = new TreeSet<UsedNonce>();

    /**
     * Allow objects that are no longer useful to become garbage.
     * 
     * @return the earliest point in time at which another call will release
     *         some garbage, or null to indicate there's nothing currently
     *         stored that will become garbage in future. This value may change,
     *         each time releaseGarbage or validateNonce is called.
     */
    //public Date releaseGarbage() {
    //    return removeOldNonces(currentTimeMsec());
    //}

    /**
     * Remove usedNonces with timestamps that are too old to be valid.
     */
    //private Date removeOldNonces(long currentTimeMsec) {
    //    UsedNonce next = null;
    //    UsedNonce min = new UsedNonce((currentTimeMsec - maxTimestampAgeMsec + 500) / 1000L);
    //    synchronized (usedNonces) {
    //        // Because usedNonces is a TreeSet, its iterator produces
    //        // elements from oldest to newest (their natural order).
    //        for (Iterator<UsedNonce> iter = usedNonces.iterator(); iter.hasNext();) {
    //            UsedNonce used = iter.next();
    //            if (min.compareTo(used) <= 0) {
    //                next = used;
    //                break; // all the rest are also new enough
    //            }
    //            iter.remove(); // too old
    //        }
    //    }
    //    if (next == null)
    //        return null;
    //    return new Date((next.getTimestamp() * 1000L) + maxTimestampAgeMsec + 500);
    //}

    /** {@inherit} 
     * @throws URISyntaxException */
    public void validateMessage(OAuth2Message message, OAuth2Accessor accessor)
    throws OAuth2Exception, IOException, URISyntaxException {
        //checkSingleParameters(message);
        //validateClientIdWithPassword(message, accessor);
        //validateCode(message,accessor);
        // vesion check should be done somewhreelse
        //validateVersion(message);
        //validateRedirectURL(message);
        //validateTimestampAndNonce(message);
        //validateSignature(message, accessor);
    }

    
    /** {@inherit} 
     * @throws URISyntaxException */
    public void validateRequestMessageForAuthorization(OAuth2Message message,OAuth2Client client)
    throws OAuth2Exception, IOException, URISyntaxException {
        //checkSingleParameters(message);
        validateResponseType(message);
        validateRedirectUri(message,client);
        validateScope(message,client);
    }
    
    /** {@inherit} 
     * @throws URISyntaxException */
    public void validateRequestMessageForAccessToken(OAuth2Message message, OAuth2Accessor accessor)
    throws OAuth2Exception, IOException, URISyntaxException {
        //checkSingleParameters(message);
        validateClientIdWithPassword(message, accessor);
        //validateCode(message,accessor);
        validateRedirectUri(message, accessor.client);
        //validateTimestampAndNonce(message);
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
     * Throw an exception if resource owner's username does not much his or her password.
     */
    protected void validateUsernameWithPasswordOfResourceOwner(OAuth2Message message, OAuth2Accessor accessor)
    throws IOException, OAuth2Exception {
        String username = message.getParameter(OAuth2.USERNAME);
        String password = message.getParameter(OAuth2.PASSWORD);

        // you will check if the resource owner's password is OK.

    }

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
                        //problem.setParameter(OAuth2.ERROR, OAuth2.INVALID_CLIENT);
                        // problem.setParameter(OAuth2.ERROR_DESCRIPTION,"The Client ID is required parameter.");
                        // problem.setParameter(OAuth2.ERROR_URI,http://example.com/error);
                        throw problem;
                    }else{
                        /* credential check. Spec(draft-ietf-oauth-v2-10) says wa have to chchek Authorization parameter
                       * with Basic Authentication and client_secret parameter.*/

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
            //double version = Double.parseDouble(versionString);
            if (!client_id.equals(accessor.client.clientId)) {
                OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.Problems.CLIENT_ID_MISMATCH);
                //problem.setParameter(OAuth2.ERROR, OAuth2.INVALID_CLIENT);
                // problem.setParameter(OAuth2.ERROR_DESCRIPTION,"The Client ID is required parameter.");
                // problem.setParameter(OAuth2.ERROR_URI,http://example.com/error);
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
            	//}else if(){
            		/* basic authentication*/
            	}else{
            		OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.Problems.PARAMETER_ABSENT);
            		problem.setParameter("parameter_name",OAuth2.CLIENT_SECRET);
            		throw problem;
            	}
            }
            
        } else{
        	OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.Problems.PARAMETER_ABSENT);
        	problem.setParameter("parameter_name",OAuth2.CLIENT_ID);
    		//roblem.setParameter(OAuth2.ERROR, OAuth2.INVALID_REQUEST);
            // problem.setParameter(OAuth2.ERROR_DESCRIPTION,"The Client ID is required parameter.");
            // problem.setParameter(OAuth2.ERROR_URI,http://example.com/error);
            
            throw problem;
        }
    }
    
    //protected void validateCode(OAuth2Message message, OAuth2Accessor accessor)
    //throws OAuthException, IOException {
    //    String code = message.getParameter(OAuth2.CODE);
    //    if (code != null) {
            //double version = Double.parseDouble(versionString);
    //        if (!code.equals(accessor.code)) {
    //            OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.Problems.CODE_UNKNOWN);
                //problem.setParameter(OAuth.Problems.OAUTH_ACCEPTABLE_VERSIONS, minVersion + "-" + maxVersion);
    //            throw problem;
    //        }
    //    } else{
        	// throw something
    //    }
    //}


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

    protected void validateScope(OAuth2Message message, OAuth2Client client)
            throws OAuth2Exception, IOException {
        String scope = message.getParameter(OAuth2.SCOPE);
        if (scope != null) {
            // TODO Check the scope is valid or not(maybe it is up to client??). And if not, throw exception
            if(scope.equals("invalid")){
                OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_SCOPE);
                throw problem;
            }
        }
    }

    /* For now, only response_type=code is supported */ 
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
        	problem.setParameter("parameter_name",OAuth2.RESPONSE_TYPE);
        	throw problem;
        	
        }
        
    }


    /** Get the number of milliseconds since midnight, January 1, 1970 UTC. */
    protected long currentTimeMsec() {
        return System.currentTimeMillis();
    }

    /**
     * Selected parameters from an OAuth request, in a form suitable for
     * detecting duplicate requests. The implementation is optimized for the
     * comparison operations (compareTo, equals and hashCode).
     * 
     * @author John Kristian
     */
    //private static class UsedNonce implements Comparable<UsedNonce> {
        /**
         * Construct an object containing the given timestamp, nonce and other
         * parameters. The order of parameters is significant.
         */
    //    UsedNonce(long timestamp, String... nonceEtc) {
    //        StringBuilder key = new StringBuilder(String.format("%20d", Long.valueOf(timestamp)));
            // The blank padding ensures that timestamps are compared as numbers.
    //        for (String etc : nonceEtc) {
    //            key.append("&").append(etc == null ? " " : OAuth.percentEncode(etc));
                // A null value is different from "" or any other String.
    //        }
    //        sortKey = key.toString();
    //    }

    //    private final String sortKey;

       // long getTimestamp() {
       //     int end = sortKey.indexOf("&");
       //     if (end < 0)
       //         end = sortKey.length();
       //     return Long.parseLong(sortKey.substring(0, end).trim());
       // }

        /**
         * Determine the relative order of <code>this</code> and
         * <code>that</code>, as specified by Comparable. The timestamp is most
         * significant; that is, if the timestamps are different, return 1 or
         * -1. If <code>this</code> contains only a timestamp (with no nonce
         * etc.), return -1 or 0. The treatment of the nonce etc. is murky,
         * although 0 is returned only if they're all equal.
         */
       // public int compareTo(UsedNonce that) {
       //     return (that == null) ? 1 : sortKey.compareTo(that.sortKey);
       // }

       // @Override
       // public int hashCode() {
       //     return sortKey.hashCode();
       // }

        /**
         * Return true iff <code>this</code> and <code>that</code> contain equal
         * timestamps, nonce etc., in the same order.
         */
       // @Override
       // public boolean equals(Object that) {
       //     if (that == null)
       //         return false;
       //     if (that == this)
       //         return true;
       //     if (that.getClass() != getClass())
       //        return false;
       //     return sortKey.equals(((UsedNonce) that).sortKey);
       // }

       // @Override
       // public String toString() {
       //     return sortKey;
       // }
    //}
}
