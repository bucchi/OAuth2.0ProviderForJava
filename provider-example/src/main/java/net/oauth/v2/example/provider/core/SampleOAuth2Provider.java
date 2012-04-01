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

package net.oauth.v2.example.provider.core;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import net.oauth.v2.OAuth2;
import net.oauth.v2.OAuth2Accessor;
import net.oauth.v2.OAuth2Client;
import net.oauth.v2.OAuth2Exception;
import net.oauth.v2.OAuth2Message;
import net.oauth.v2.OAuth2ProblemException;
import net.oauth.v2.OAuth2Validator;
import net.oauth.v2.SimpleOAuth2Validator;
import net.oauth.v2.server.OAuth2Servlet;

/**
 * Utility methods for providers that store clients, tokens as Accessor object in
 * local cache (HashSet). Consumer key is used as the name, and its credentials are 
 * stored in HashSet.
 *
 * @author Yutaka Obuchi
 */
public class SampleOAuth2Provider {

    public static final OAuth2Validator VALIDATOR = new SimpleOAuth2Validator();

    private static final Map<String, OAuth2Client> ALL_CLIENTS 
                    = Collections.synchronizedMap(new HashMap<String,OAuth2Client>(10));
    
    private static final Collection<OAuth2Accessor> ALL_TOKENS = new HashSet<OAuth2Accessor>();

    private static Properties consumerProperties = null;

    /*
     * load clients data from properties file
     */
    public static synchronized void loadConsumers() throws IOException {
        Properties p = consumerProperties;
        if (p == null) {
            p = new Properties();
            String resourceName = ""
                    + SampleOAuth2Provider.class.getPackage().getName().replace(
                    ".", "/") + "/provider.properties";
            URL resource = SampleOAuth2Provider.class.getClassLoader().getResource(resourceName);
            if (resource == null) {
                throw new IOException("resource not found: " + resourceName);
            }
            InputStream stream = resource.openStream();
            try {
                p.load(stream);
            } finally {
                stream.close();
            }
        }
        consumerProperties = p;
        
        // for each entry in the properties file create a OAuthConsumer
        for(Map.Entry prop : p.entrySet()) {
            String consumer_key = (String) prop.getKey();
            // make sure it's key not additional properties
            if(!consumer_key.contains(".")){
                String consumer_secret = (String) prop.getValue();
                if(consumer_secret != null){
                    String consumer_description = (String) p.getProperty(consumer_key + ".description");
                    String consumer_callback_url =  (String) p.getProperty(consumer_key + ".callbackURL");
                    // Create OAuthConsumer w/ key and secret
                    OAuth2Client client = new OAuth2Client(
                            consumer_callback_url, 
                            consumer_key, 
                            consumer_secret);
                    client.setProperty("name", consumer_key);
                    client.setProperty("description", consumer_description);
                    ALL_CLIENTS.put(consumer_key, client);
                }
            }
        }
        
    }
    /*
     * get client with the value of client_id parameter
     */
    public static synchronized OAuth2Client getClient(
            OAuth2Message requestMessage)
            throws IOException, OAuth2ProblemException {
        
        OAuth2Client client = null;
        // try to load from local cache if not throw exception
        String client_id = requestMessage.getClientId();
        
        client = SampleOAuth2Provider.ALL_CLIENTS.get(client_id);
        
        if(client == null) {
            OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_CLIENT);
            if(requestMessage.getParameter(OAuth2.STATE)!=null){
            	problem.setParameter(OAuth2.STATE, requestMessage.getParameter(OAuth2.STATE));
            }
            throw problem;
        }
        
        return client;
    }

    /*
     * get client with the value of Authoraization header
     */
    public static synchronized OAuth2Client getClientFromAuthHeader(
            OAuth2Message requestMessage)
            throws IOException, OAuth2ProblemException {

        OAuth2Client client = null;
        // try to load from local cache if not throw exception
        String authz = requestMessage.getHeader("Authorization");
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
                    client = SampleOAuth2Provider.ALL_CLIENTS.get(user);


                }
            }
        }
        if(client == null) {
            OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_CLIENT);
            throw problem;
        }

        return client;
    }

    /**
     * Get the accessor for the given code.
     */
    public static synchronized OAuth2Accessor getAccessorByCode(OAuth2Message requestMessage)
            throws IOException, OAuth2ProblemException {
        
        // try to load from local cache if not throw exception
        String code = requestMessage.getCode();
        if(code == null){
        	OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_REQUEST);
            throw problem;
        }
        OAuth2Accessor accessor = null;
        for (OAuth2Accessor a : SampleOAuth2Provider.ALL_TOKENS) {
            if(a.code != null) {
                if (a.code.equals(code)) {
                    accessor = a;
                    break;
                }
            }
        }
        
        if(accessor == null){
            OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_REQUEST);

            throw problem;
        }
        
        return accessor;
    }

    /**
     * Get the accessor for the given Refresh Token.
     */
    public static synchronized OAuth2Accessor getAccessorByRefreshToken(OAuth2Message requestMessage)
    throws IOException, OAuth2ProblemException {

    	// try to load from local cache if not throw exception
    	String refreshToken = requestMessage.getParameter(OAuth2.REFRESH_TOKEN);
    	if(refreshToken == null){
        	OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_REQUEST);
            throw problem;
        }
    	OAuth2Accessor accessor = null;
    	for (OAuth2Accessor a : SampleOAuth2Provider.ALL_TOKENS) {
    		if(a.refreshToken != null) {
    			if (a.refreshToken.equals(refreshToken)) {
    				accessor = a;
    				break;
    			}
    		}
    	}

    	if(accessor == null){
    		OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.INVALID_GRANT);

    		throw problem;
    	}

    	return accessor;
    }
    /**
     * Set mark the accessor as authorized
     */
    public static synchronized void markAsAuthorized(OAuth2Accessor accessor, String userId)
            throws OAuth2Exception {
        
        
        // first remove the accessor from cache
        ALL_TOKENS.remove(accessor);
        
        accessor.setProperty("user", userId);   
        accessor.setProperty("authorized", Boolean.TRUE);
        
        // update token in local cache
        ALL_TOKENS.add(accessor);
    }
    

    /**
     * Generate an access token and fresh token.
     * 
     * @throws OAuth2Exception
     */
    public static synchronized void generateAccessAndRefreshToken(OAuth2Accessor accessor)
            throws OAuth2Exception {

        // generate access token and refresh token
        String client_id = (String) accessor.client.clientId;
        String redirect_uri = (String) accessor.client.redirectUri;
        

        
        // for now use md5 of client_id + current time as token
        String access_token_data = client_id + System.nanoTime();
        String accessToken = DigestUtils.md5Hex(access_token_data);
        
        String refresh_token_data = redirect_uri + System.nanoTime();
        String refreshToken = DigestUtils.md5Hex(refresh_token_data);
        // first remove the accessor from cache
        ALL_TOKENS.remove(accessor);
        
        accessor.accessToken = accessToken;
        accessor.tokenType = "bearer";
        accessor.refreshToken = refreshToken;
        
        // update token in local cache
        ALL_TOKENS.add(accessor);
    }

    /*
     * generate authorization code
     */
    public static synchronized void generateCode(
            OAuth2Accessor accessor)
            throws OAuth2Exception {

        // generate authorization code
        String client_id = (String) accessor.client.clientId;

        
        // for now use md5 of client_id + current time as token
        String code_data = client_id + System.nanoTime();
        String code = DigestUtils.md5Hex(code_data);
        
        accessor.code = code;
        
        // add to the local cache
        ALL_TOKENS.add(accessor);
        
    }

    /*
     * handle exceptions
     */
    public static void handleException(Exception e, HttpServletRequest request,
            HttpServletResponse response, boolean sendBodyInJson, boolean withAuthHeader)
            throws IOException, ServletException {
    	
    	String realm = null;

    	OAuth2Servlet.handleException(request, response, e, realm, sendBodyInJson, withAuthHeader); 
    }
    

}
