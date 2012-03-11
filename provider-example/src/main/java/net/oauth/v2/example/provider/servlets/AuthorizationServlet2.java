/*
 * Copyright 2010,2011.2012 Yutaka Obuchi
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
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.oauth.v2.OAuth2;
import net.oauth.v2.OAuth2.Parameter;
import net.oauth.v2.OAuth2Accessor;
import net.oauth.v2.OAuth2Client;
import net.oauth.v2.OAuth2Message;
import net.oauth.v2.OAuth2ProblemException;
import net.oauth.v2.server.OAuth2Servlet;


import net.oauth.v2.example.provider.core.SampleOAuth2Provider;

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
            
            sendToAuthorizePage(request, response, client);

        
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
            
            OAuth2Client client = SampleOAuth2Provider.getClient(requestMessage);
            
            String userId = request.getParameter("userId");
            if(userId == null){
            	SampleOAuth2Provider.VALIDATOR.validateRequestMessageForAuthorization(requestMessage,client);
                sendToAuthorizePage(request, response, client);
            }
            
            OAuth2Accessor accessor = new OAuth2Accessor(client);            
            
            // set userId in accessor and mark it as authorized
            SampleOAuth2Provider.markAsAuthorized(accessor, userId);


            String requested = requestMessage.getParameter(OAuth2.RESPONSE_TYPE);
            if (requested.equals(OAuth2.ResponseType.CODE)) {
                SampleOAuth2Provider.generateCode(accessor);
                returnToConsumer(request, response, accessor);
            }else if (requested.equals(OAuth2.ResponseType.TOKEN)){
                // generate refresh token here but do not send back that
                SampleOAuth2Provider.generateAccessAndRefreshToken(accessor);
                String redirect_uri = request.getParameter(OAuth2.REDIRECT_URI);
                String state = request.getParameter(OAuth2.STATE);
                
                List<Parameter> list = new ArrayList<Parameter>(5);
                list.add(new Parameter(OAuth2.ACCESS_TOKEN,accessor.accessToken));
                list.add(new Parameter(OAuth2.TOKEN_TYPE,accessor.tokenType));
                list.add(new Parameter(OAuth2.EXPIRES_IN,"3600"));
                if(accessor.scope!=null) list.add(new Parameter(OAuth2.SCOPE,accessor.scope));
                if(state != null){
                    list.add(new Parameter(OAuth2.STATE, state));
                }
                
                redirect_uri = OAuth2.addParametersAsFragment(redirect_uri,list);
                response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
                response.setHeader("Location", OAuth2.decodePercent(redirect_uri));

            }else if (requested.equals(OAuth2.ResponseType.CODE_AND_TOKEN)){
                //TODO
            }else{
                //TODO
            }

            

            
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


        response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
        response.setHeader("Location", OAuth2.decodePercent(redirect_uri));

    }

    private static final long serialVersionUID = 1L;

}
