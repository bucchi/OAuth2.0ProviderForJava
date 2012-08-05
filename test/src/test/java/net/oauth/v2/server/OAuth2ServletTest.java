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

package net.oauth.v2.server;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.net.URLDecoder;
import junit.framework.TestCase;
import com.meterware.servletunit.ServletRunner;
import com.meterware.servletunit.ServletUnitClient;
import com.meterware.servletunit.InvocationContext;
import com.meterware.httpunit.PostMethodWebRequest;
import com.meterware.httpunit.GetMethodWebRequest;
import com.meterware.httpunit.WebRequest;
import com.meterware.httpunit.WebResponse;

import javax.servlet.http.HttpServletResponse;

import net.oauth.v2.*;

//import net.oauth.v2.OAuth2.Parameter;

public class OAuth2ServletTest extends TestCase
{
    private static final String[][] OAUTH_PARAMETERS =
    // label, inputs, expected result
    { { "NormalJSONResponse body check", "grant_type=authorization_code&client_id=s6BhdRkqt3&code=i1WsRn1uB1&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb","authorization_code","s6BhdRkqt3","i1WsRn1uB1","https%3A%2F%2Fclient.example.com%2Fcb"} 
    };
    
     
    public void testHandleExceptionByJson() throws Exception
    {	
    	
        ServletRunner sr = new ServletRunner();
		ServletUnitClient sc = sr.newClient();
		WebRequest request   = new PostMethodWebRequest( "https://test.meterware.com/myServlet" );
		InvocationContext ic = sc.newInvocation( request );
		
        OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.UNSUPPORTED_RESPONSE_TYPE);
        // if you do not specify status code 200 here response does not inluce anything 
        problem.setParameter(OAuth2ProblemException.HTTP_STATUS_CODE,new Integer(200));
        HttpServletResponse hsr = ic.getResponse();
        OAuth2Servlet.handleException(ic.getRequest(),hsr,problem,null,true,false);
        
        WebResponse response   = ic.getServletResponse();
    
        assertEquals("ErrorJSONResponse Body chcek", "{"+toStringWithQuotation("error")+":"+toStringWithQuotation("unsupported_response_type")+"}", response.getText());
        assertEquals("ErrorJSONResponse ContentType check", "application/json", response.getContentType()); 

            
        
    }
    
    public void testHandleExceptionByRedirectURL() throws Exception
    {	
    	
        ServletRunner sr = new ServletRunner();
		ServletUnitClient sc = sr.newClient();
		WebRequest request   = new PostMethodWebRequest( "https://test.meterware.com/myServlet" );
		InvocationContext ic = sc.newInvocation( request );
		
        OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.UNSUPPORTED_RESPONSE_TYPE);
        problem.setParameter(OAuth2ProblemException.HTTP_STATUS_CODE,new Integer(302));
        //problem.getParameters().put(OAuth2.REDIRECT_URI,"https://client.example.com/cb");
        problem.setParameter(OAuth2.REDIRECT_URI,"https://client.example.com/cb");
        HttpServletResponse hsr = ic.getResponse();
        OAuth2Servlet.handleException(ic.getRequest(),hsr,problem,null,false,false);
        
    	
        WebResponse response   = ic.getServletResponse();
            
        assertEquals("ErroeRedirectResponse Location chceck", "https://client.example.com/cb?error=unsupported_response_type", response.getHeaderField(OAuth2ProblemException.HTTP_LOCATION));   
        assertEquals("ErrorRedirectResponse Code check", "302", new Integer(response.getResponseCode()).toString());
            
        
    }

    public void testHandleExceptionByRedirectURL2() throws Exception
    {

        ServletRunner sr = new ServletRunner();
        ServletUnitClient sc = sr.newClient();
        WebRequest request   = new PostMethodWebRequest( "https://test.meterware.com/myServlet" );
        InvocationContext ic = sc.newInvocation( request );

        OAuth2ProblemException problem = new OAuth2ProblemException(OAuth2.ErrorCode.UNSUPPORTED_RESPONSE_TYPE);
        problem.setParameter(OAuth2ProblemException.HTTP_STATUS_CODE,new Integer(302));
        //problem.getParameters().put(OAuth2.REDIRECT_URI,"https://client.example.com/cb");
        problem.setParameter(OAuth2.REDIRECT_URI,"https://client.example.com/cb");
        HttpServletResponse hsr = ic.getResponse();
        OAuth2Servlet.handleException(ic.getRequest(),hsr,problem,null,false,false);


        WebResponse response   = ic.getServletResponse();

        assertEquals("ErroeRedirectResponse Location chceck", "https://client.example.com/cb?error=unsupported_response_type", response.getHeaderField(OAuth2ProblemException.HTTP_LOCATION));
        assertEquals("ErrorRedirectResponse Code check", "302", new Integer(response.getResponseCode()).toString());


    }

    private static final String toStringWithQuotation(Object from) {
    	
    	StringBuffer sb;
    	if(from == null || from.toString().length() == 0)
    	{
    		sb = new StringBuffer(2);
            sb.append('"');
            sb.append('"');
            return sb.toString();
    	}
    	int         len = from.toString().length();
        sb = new StringBuffer(len + 2);
        sb.append('"');
        sb.append(from.toString());
        sb.append('"');
        return sb.toString();
    }
    public void testSendFormInJson() throws Exception
    {	
    	
    	for (String[] testCase : OAUTH_PARAMETERS) {
    		ServletRunner sr = new ServletRunner();
    		ServletUnitClient sc = sr.newClient();
    		WebRequest request   = new PostMethodWebRequest( "https://test.meterware.com/myServlet" );   		
    		InvocationContext ic = sc.newInvocation( request );      
       
            String label = testCase[0];
            //String realm = testCase[1];
            List<OAuth2.Parameter> parameters = decodeForm(testCase[1]);
            OAuth2Servlet.sendFormInJson(ic.getResponse(),parameters);
            WebResponse response   = ic.getServletResponse();
            String expectedGrantType = testCase[2];
            String expectedClientId = testCase[3];
            //String expectedSecret = testCase[5];
            String expectedCode = testCase[4];
            String expectedRedirectURI = testCase[5];
            assertEquals(label, "{"+toStringWithQuotation("grant_type")+":"+toStringWithQuotation(expectedGrantType)+","
            		                  +toStringWithQuotation("client_id")+":"+toStringWithQuotation(expectedClientId)+","
            		          //+toStringWithQuotation("client_secret")+":"+toStringWithQuotation(expectedSecret)+","
            		        		  +toStringWithQuotation("code")+":"+toStringWithQuotation(expectedCode)+","
                    		          +toStringWithQuotation("redirect_uri")+":"+toStringWithQuotation(expectedRedirectURI)+"}", response.getText());
            
        }
    }
    public void testGetMessage() throws Exception
    {	
    	
    	for (String[] testCase : OAUTH_PARAMETERS) {
    		ServletRunner sr = new ServletRunner();
    		ServletUnitClient sc = sr.newClient();
    		WebRequest request   = new PostMethodWebRequest( "https://test.meterware.com/myServlet" );
    		request.setParameter( "grant_type", testCase[2] );
    		request.setParameter( "client_id", testCase[3] );
    		//request.setParameter( "client_secret", testCase[5] );
    		request.setParameter( "code", testCase[4] );
    		request.setParameter( "redirect_uri", testCase[5] );    		
    		InvocationContext ic = sc.newInvocation( request );
    		OAuth2Message message = OAuth2Servlet.getMessage(ic.getRequest(),"https://test.meterware.com/myServlet");
    		
            String label = testCase[0];
            //String realm = testCase[1];
            String expectedGrantType = testCase[2];
            String expectedClientId = testCase[3];
            //String expectedSecret = testCase[4];
            String expectedCode = testCase[4];
            String expectedRedirectURI = testCase[5];
            
            assertEquals("Message check", expectedGrantType, message.getParameter(OAuth2.GRANT_TYPE));
            assertEquals("Message check", expectedClientId, message.getClientId());
            //assertEquals(label, expectedSecret, message.getParameter(OAuth2.CLIENT_SECRET));
            assertEquals("Message check", expectedCode, message.getCode());
            assertEquals("Message check", expectedRedirectURI, message.getParameter(OAuth2.REDIRECT_URI));
        }
    }
    public void testGetRequestURL() throws Exception
    {	
    	ServletRunner sr = new ServletRunner();
    	ServletUnitClient sc = sr.newClient();
        WebRequest request   = new GetMethodWebRequest( "http://test.meterware.com/myServlet" );
        request.setParameter( "color", "red" );
        InvocationContext ic = sc.newInvocation( request );
        String url = OAuth2Servlet.getRequestURL(ic.getRequest());
        assertEquals("URL check", "http://test.meterware.com/myServlet?color=red", url);        
    }
    
    
    public static List<OAuth2.Parameter> decodeForm(String form) {
            List<OAuth2.Parameter> list = new ArrayList<OAuth2.Parameter>();
            if (!isEmpty(form)) {
                for (String nvp : form.split("\\&")) {
                    int equals = nvp.indexOf('=');
                    String name;
                    String value;
                    if (equals < 0) {
                        name = decodePercent(nvp);
                        value = null;
                    } else {
                        name = decodePercent(nvp.substring(0, equals));
                        value = decodePercent(nvp.substring(equals + 1));
                    }
                    list.add(new OAuth2.Parameter(name, value));
                }
            }
            return list;
        }
    
    public static String decodePercent(String s) {
        try {
            return URLDecoder.decode(s, "UTF-8");
            // This implements http://oauth.pbwiki.com/FlexibleDecoding
        } catch (java.io.UnsupportedEncodingException wow) {
            throw new RuntimeException(wow.getMessage(), wow);
        }
    }
    
    public static boolean isEmpty(String str) {
    	return (str == null) || (str.length() == 0);
    }
}
