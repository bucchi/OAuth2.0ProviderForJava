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
 * Copyright 2007 Netflix, Inc.
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
package net.oauth.v2.server;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Collections;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.oauth.v2.OAuth2;
import net.oauth.v2.OAuth2Message;
import net.oauth.v2.OAuth2ProblemException;

/**
 * Utility methods for servlets that implement OAuth2.0.
 * 
 * @author Yutaka Obuchi
 */
public class OAuth2Servlet {

    /**
     * Extract the parts of the given request that are relevant to OAuth.
     * Parameters include OAuth Authorization headers and the usual request
     * parameters in the query string and/or form encoded body. The header
     * parameters come first, followed by the rest in the order they came from
     * request.getParameterMap().
     * 
     * @param URL
     *            the official URL of this service; that is the URL a legitimate
     *            client would use to compute the digital signature. If this
     *            parameter is null, this method will try to reconstruct the URL
     *            from the HTTP request; which may be wrong in some cases.
     */
    public static OAuth2Message getMessage(HttpServletRequest request, String URL) {
        if (URL == null) {
            URL = request.getRequestURL().toString();
        }
        int q = URL.indexOf('?');
        if (q >= 0) {
            URL = URL.substring(0, q);
            // The query string parameters will be included in
            // the result from getParameters(request).
        }
        return new HttpRequestMessage(request, URL);
    }

    /** Reconstruct the requested URL, complete with query string (if any). */
    public static String getRequestURL(HttpServletRequest request) {
        StringBuffer url = request.getRequestURL();
        String queryString = request.getQueryString();
        if (queryString != null) {
            url.append("?").append(queryString);
        }
        return url.toString();
    }

    public static void handleException(HttpServletResponse response,
            Exception e, String realm) throws IOException, ServletException {
        handleException(null, response, e, realm, true,true);
    }
    
    public static final Set<String> SEND_BACK_ERROR_PARAMETERS = constructParameters();

    private static Set<String> constructParameters() {
        Set<String> s = new HashSet<String>();
        for (String p : new String[] { OAuth2.ERROR, OAuth2.ERROR_DESCRIPTION, OAuth2.ERROR_URI,
                OAuth2.STATE}) {
            s.add(p);
        }
        return Collections.unmodifiableSet(s);
    }

    private static Object getHttpCode(OAuth2ProblemException problem){

        Object httpCode = problem.getParameters().get(OAuth2ProblemException.HTTP_STATUS_CODE);
        if (httpCode == null) {
            httpCode = ERROR_TO_HTTP_CODE.get(problem.getProblem());
        }
        if (httpCode == null) {
            httpCode = SC_FORBIDDEN;
        }

        return httpCode;
    }


    public static void handleException(HttpServletRequest request, HttpServletResponse response,
    		Exception e, String realm, boolean sendBodyInJson, boolean withAuthHeader)
        throws IOException, ServletException {
    	
        if (e instanceof OAuth2ProblemException) {
            OAuth2ProblemException problem = (OAuth2ProblemException) e;

            Object httpCode = getHttpCode(problem);

            response.reset();
            response.setStatus(Integer.parseInt(httpCode.toString()));
            
            
            OAuth2Message message = new OAuth2Message(null, null, problem.getParameters().entrySet()); 	
            if(withAuthHeader){
            	response.addHeader("WWW-Authenticate", message.getWWWAuthenticateHeader(realm));
            }

            List<Map.Entry<String, String>> sendBackErrorParameters = new ArrayList<Map.Entry<String, String>>(SEND_BACK_ERROR_PARAMETERS.size());
            for (Map.Entry parameter : message.getParameters()) {
                if(SEND_BACK_ERROR_PARAMETERS.contains(parameter.getKey()))
                {
                    sendBackErrorParameters.add(parameter);
                }
            }

            if (sendBodyInJson) {
                sendFormInJson(response, sendBackErrorParameters);
            }else{
                String redirect_uri = constructErrorRedirectUri(message,sendBackErrorParameters);

            	response.addHeader(OAuth2ProblemException.HTTP_LOCATION,redirect_uri);
            }
        } else if (e instanceof IOException) {
            throw (IOException) e;
        } else if (e instanceof ServletException) {
            throw (ServletException) e;
        } else if (e instanceof RuntimeException) {
            throw (RuntimeException) e;
        } else {
            throw new ServletException(e);
        }
    }

    private static final Integer SC_FORBIDDEN = new Integer(HttpServletResponse.SC_FORBIDDEN);

    private static final Map<String, Integer> ERROR_TO_HTTP_CODE = OAuth2.ErrorCode.TO_HTTP_CODE;

    /** Send the given parameters as a form-encoded response body. */
    //public static void sendForm(HttpServletResponse response,
    //        Iterable<? extends Map.Entry> parameters) throws IOException {
    //    response.resetBuffer();
    //    response.setContentType(OAuth.FORM_ENCODED + ";charset="
    //            + OAuth.ENCODING);
    //    OAuth.formEncode(parameters, response.getOutputStream());
    //}

    /** Send the given parameters as a form-encoded response body. */
    public static void sendFormInJson(HttpServletResponse response,
            Iterable<? extends Map.Entry> parameters) throws IOException {
        response.resetBuffer();
        response.setContentType("application/json" + ";charset="
                + OAuth2.ENCODING);

        OAuth2.formEncodeInJson(parameters, response.getOutputStream());
    }
    /**
     * Return the HTML representation of the given plain text. Characters that
     * would have special significance in HTML are replaced by <a
     * href="http://www.w3.org/TR/html401/sgml/entities.html">character entity
     * references</a>. Whitespace is not converted.
     */
    public static String htmlEncode(String s) {
        if (s == null) {
            return null;
        }
        StringBuilder html = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            switch (c) {
            case '<':
                html.append("&lt;");
                break;
            case '>':
                html.append("&gt;");
                break;
            case '&':
                html.append("&amp;");
                // This also takes care of numeric character references;
                // for example &#169 becomes &amp;#169.
                break;
            case '"':
                html.append("&quot;");
                break;
            default:
                html.append(c);
                break;
            }
        }
        return html.toString();
    }

    public static String constructErrorRedirectUri(OAuth2Message message, Iterable<? extends Map.Entry<String, String>> parameters) throws IOException{

        //send back error info as parameters to the redirection URI query component
        String redirect_uri = message.getParameter(OAuth2.REDIRECT_URI);

        //ToDo maybe this part should be out of core code and be in example.
        String response_type = message.getParameter(OAuth2.RESPONSE_TYPE);
        if(response_type != null && response_type.equals(OAuth2.ResponseType.TOKEN)){
            redirect_uri = OAuth2.addParametersAsFragment(redirect_uri,parameters);
        } else {
            redirect_uri = OAuth2.addParameters(redirect_uri,parameters);
        }

        return redirect_uri;
    }
}
