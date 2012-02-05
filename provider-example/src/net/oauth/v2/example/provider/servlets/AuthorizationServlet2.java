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

package net.oauth.v2.example.provider.servlets;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.oauth.v2.OAuth2;
import net.oauth.v2.OAuth2Accessor;
import net.oauth.v2.OAuth2Client;
import net.oauth.v2.OAuth2Message;
import net.oauth.v2.OAuth2ProblemException;
import net.oauth.v2.example.provider.core.SampleOAuth2Provider;
import net.oauth.v2.server.OAuth2Servlet;

/**
 * Autherization request handler for OAuth2.0.
 *
 * @author Yutaka Obuchi
 */
public class AuthorizationServlet2 extends HttpServlet {
    
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try{
         SampleOAuth2Provider.loadConsumers();
        }catch(Exception e){
        	System.out.println("You could not load consumer data.");
        }
        // nothing at this point
    }
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        
    	OAuth2Message requestMessage = null;
        try{
            requestMessage = OAuth2Servlet.getMessage(request, null);
            
            OAuth2Client client = SampleOAuth2Provider.getClient(requestMessage);
            
            SampleOAuth2Provider.VALIDATOR.validateRequestMessageForAuthorization(requestMessage,client);
            
            //OAuth2Accessor accessor = new OAuth2Accessor(client);
            //OAuthAccessor accessor = SampleOAuth2Provider.getAccessor(requestMessage);
           
            //if (Boolean.TRUE.equals(accessor.getProperty("authorized"))) {
                // already authorized send the user back
            //    returnToConsumer(request, response, accessor);
            //} else {
                sendToAuthorizePage(request, response, client);
            //}
        
        } catch (Exception e){
            Boolean sendBodyInJson = false;
            Boolean withAuthHeader = false;
            if (e instanceof OAuth2ProblemException){
            	OAuth2ProblemException problem = (OAuth2ProblemException) e;
            	problem.setParameter(OAuth2.REDIRECT_URI,OAuth2.decodePercent(requestMessage.getParameter(OAuth2.REDIRECT_URI)));
            	problem.setParameter(OAuth2ProblemException.HTTP_STATUS_CODE,new Integer(302));
            	/* it can be removed at here */
            	if(requestMessage.getParameter(OAuth2.STATE)!=null){
                	problem.setParameter(OAuth2.STATE, requestMessage.getParameter(OAuth2.STATE));
                }
            }
            
            SampleOAuth2Provider.handleException(e, request, response, sendBodyInJson, withAuthHeader);
        }
        
        
        
    }
    
    @Override 
    public void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws IOException, ServletException{
        
        try{
            OAuth2Message requestMessage = OAuth2Servlet.getMessage(request, null);
            
            //OAuth2Accessor accessor = SampleOAuth2Provider.getAccessor(requestMessage);
            OAuth2Client client = SampleOAuth2Provider.getClient(requestMessage);
            
            String userId = request.getParameter("userId");
            if(userId == null){
            	SampleOAuth2Provider.VALIDATOR.validateRequestMessageForAuthorization(requestMessage,client);
                sendToAuthorizePage(request, response, client);
            }
            
            OAuth2Accessor accessor = new OAuth2Accessor(client);            
            
            // set userId in accessor and mark it as authorized
            SampleOAuth2Provider.markAsAuthorized(accessor, userId);
        	SampleOAuth2Provider.generateCode(accessor);
            
            returnToConsumer(request, response, accessor);
            
        } catch (Exception e){
            Boolean sendBodyInJson = false;
            Boolean withAuthHeader = false;
            if (e instanceof OAuth2ProblemException){
            	OAuth2ProblemException problem = (OAuth2ProblemException) e;
            	problem.setParameter(OAuth2ProblemException.HTTP_STATUS_CODE,new Integer(302));
            	//problem.setParameters(OAuth2ProblemException.HTTP_LOCATION,)
            }
        	SampleOAuth2Provider.handleException(e, request, response, sendBodyInJson,withAuthHeader);
        }
    }
    
    private void sendToAuthorizePage(HttpServletRequest request, 
            HttpServletResponse response, OAuth2Client client)
    throws IOException, ServletException{
        String redirect_uri = request.getParameter(OAuth2.REDIRECT_URI);
        String response_type = request.getParameter(OAuth2.RESPONSE_TYPE);
        
        // maybe redirect_uri check shold be done OAuth2Validator
        //if(redirect_uri == null || redirect_uri.length() <=0) {
            // throw exception
        //}
        String client_description = (String)client.getProperty("description");
        request.setAttribute("CLIE_DESC", client_description);
        request.setAttribute("REDIRECT_URI", redirect_uri);
        request.setAttribute("RESPONSE_TYPE", response_type);
        request.setAttribute("CLIE_ID", client.clientId);
        request.getRequestDispatcher //
                    ("/authorize2.jsp").forward(request,
                        response);
        
    }
    
    private void returnToConsumer(HttpServletRequest request, 
            HttpServletResponse response, OAuth2Accessor accessor)
    throws IOException, ServletException{
        // send the user back to site's callBackUrl
        String redirect_uri = request.getParameter(OAuth2.REDIRECT_URI);
        //if("none".equals(callback) 
        //    && accessor.consumer.callbackURL != null 
        //        && accessor.consumer.callbackURL.length() > 0){
            // first check if we have something in our properties file
        //    callback = accessor.consumer.callbackURL;
        //}
        //generate code and set it to accessor
        //if( "none".equals(callback) ) {
            // no call back it must be a client
       //     response.setContentType("text/plain");
       //     PrintWriter out = response.getWriter();
       //     out.println("You have successfully authorized '" 
       //             + accessor.consumer.getProperty("description") 
       //             + "'. Please close this browser window and click continue"
       //             + " in the client.");
       //     out.close();
       // } else {
            // if callback is not passed in, use the callback from config
            //if(redirect_uri == null || redirect_uri.length() <=0 ){
                //callback = accessor.consumer.callbackURL;
                //String token = accessor.requestToken;
            	
            	// send back error
            //}else{
            //if (token != null) {
                redirect_uri = OAuth2.addParameters(redirect_uri, OAuth2.CODE, accessor.code);
            //}
            //}
            response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
            response.setHeader("Location", redirect_uri);
        //}
    }

    private static final long serialVersionUID = 1L;

}
