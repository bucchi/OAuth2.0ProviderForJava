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

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.net.URLDecoder;

import junit.framework.TestCase;
import com.meterware.servletunit.*;
import com.meterware.httpunit.*;
import net.oauth.v2.*;
import net.oauth.v2.example.provider.core.SampleOAuth2Provider;

import org.mortbay.jetty.testing.ServletTester;
import org.mortbay.jetty.testing.HttpTester;

/**
 * @author Yutaka Obuchi
 */
public class AccessTokenServlet2Test extends TestCase {

    //private long currentTimeMsec;
    //private SimpleOAuth2Validator validator;
    //private static final Map<String, String> PROBLEM_TO_ERROR_CODE = OAuth2.Problems.TO_ERROR_CODE;


    //@Override
    //protected void setUp() throws Exception {
    //    currentTimeMsec = (System.currentTimeMillis() / 1000) * 1000;
    //    validator = new SimpleOAuth2Validator() {
    //        @Override
    //        protected long currentTimeMsec() {return currentTimeMsec;}
    //    };
    //}

	public void testDoPost1() throws Exception {
		// generate code first
        SampleOAuth2Provider.loadConsumers();
		OAuth2Client o2c = new OAuth2Client("http://localhost/CookieJar/Callback","myKey","mySecret");
    	o2c.setProperty("name",o2c.clientId);
    	OAuth2Accessor o2a = new OAuth2Accessor(o2c);
    	o2a.setProperty("authorized",true);
    	SampleOAuth2Provider.generateCode(o2a);

        ServletTester tester=new ServletTester();
        tester.setContextPath("/test");
        tester.addServlet(AccessTokenServlet2.class, "/token");
        tester.start();

        String postParameter = "grant_type=authorization_code&code="+o2a.code+
                "&client_id=myKey&client_secret=mySecret&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%2FCookieJar%2FCallback";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("POST");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/token");
        request.setVersion("HTTP/1.1");
        request.setHeader("Content-Type","application/x-www-form-urlencoded;charset=UTF-8");
        request.setContent(postParameter);

        response.parse(tester.getResponses(request.generate()));

        assertEquals(200,response.getStatus());
        assertEquals("{\"access_token\":\"" + o2a.accessToken +
                "\",\"token_type\":\"" + o2a.tokenType +
                "\",\"expires_in\":\"3600\",\"refresh_token\":\"" + o2a.refreshToken +
                                        "\"}",response.getContent());
		
    }

    /*
     * Error Case: invalid client secret with error=invalid_client
     */
    public void testDoPost2() throws Exception {
        // generate code first
        SampleOAuth2Provider.loadConsumers();
        OAuth2Client o2c = new OAuth2Client("http://localhost/CookieJar/Callback","myKey","mySecret");
        o2c.setProperty("name",o2c.clientId);
        OAuth2Accessor o2a = new OAuth2Accessor(o2c);
        o2a.setProperty("authorized",true);
        SampleOAuth2Provider.generateCode(o2a);

        ServletTester tester=new ServletTester();
        tester.setContextPath("/test");
        tester.addServlet(AccessTokenServlet2.class, "/token");
        tester.start();

        String postParameter = "grant_type=authorization_code&code="+o2a.code+
                "&client_id=myKey&client_secret=invalidSecret&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%2FCookieJar%2FCallback";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("POST");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/token");
        request.setVersion("HTTP/1.1");
        request.setHeader("Content-Type","application/x-www-form-urlencoded;charset=UTF-8");
        request.setContent(postParameter);

        response.parse(tester.getResponses(request.generate()));

        assertEquals(401,response.getStatus());
        assertEquals("{\"error\":\"invalid_client\"}",response.getContent());

    }
/*
	
	public void testGetAccessor() throws Exception {
    	OAuth2Client o2c = new OAuth2Client("https://client.example.com/cb","s6BhdRkqt3","gX1fBat3bV");
    	OAuth2Accessor o2a = new OAuth2Accessor(o2c);
        
        SampleOAuth2Provider.generateCode(o2a);
        String parameters = "grant_type=authorization_code&client_id=s6BhdRkqt3&client_secret=invalid&code="+o2a.code+"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
        OAuth2Message msg = new OAuth2Message("", "", decodeForm(parameters));
        
        OAuth2Accessor cachedAccessor = SampleOAuth2Provider.getAccessor(msg);
        assertSame(o2a, cachedAccessor);
    }
    
    public void testGenerateCode() throws Exception {
    	OAuth2Client o2c = new OAuth2Client("https://client.example.com/cb","s6BhdRkqt3","gX1fBat3bV");
    	OAuth2Accessor o2a = new OAuth2Accessor(o2c);
        
        SampleOAuth2Provider.generateCode(o2a);
        assertNotNull(o2a.code);
    }*/
    /*public void testClientIdWithInvalidPassword() throws Exception {
    	OAuth2Client o2c = new OAuth2Client("https://client.example.com/cb","s6BhdRkqt3","gX1fBat3bV");
    	OAuth2Accessor o2a = new OAuth2Accessor(o2c);
        //validator.checkSingleParameters(new OAuthMessage("", "", OAuth.decodeForm("x=y&x=y")));
        String parameters = "grant_type=authorization_code&client_id=s6BhdRkqt3&client_secret=invalid&code=i1WsRn1uB1&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
        OAuth2Message msg = new OAuth2Message("", "", decodeForm(parameters));
        try {
            validator.validateClientIdWithPassword(msg,o2a);
            fail("invalid password");
        } catch (OAuth2ProblemException expected) {
            //assertEquals(OAuth.Problems.PARAMETER_REJECTED, expected.getProblem());
        	assertEquals(OAuth2.Problems.CLIENT_SECRET_MISMATCH, expected.getProblem());
        	assertEquals("unauthorized_client", PROBLEM_TO_ERROR_CODE.get(OAuth2.Problems.CLIENT_SECRET_MISMATCH));
        }
    }
    public void testNoClientId() throws Exception {
    	OAuth2Client o2c = new OAuth2Client("https://client.example.com/cb","s6BhdRkqt3","gX1fBat3bV");
    	OAuth2Accessor o2a = new OAuth2Accessor(o2c);
        //validator.checkSingleParameters(new OAuthMessage("", "", OAuth.decodeForm("x=y&x=y")));
        String parameters = "grant_type=authorization_code&client_secret=gX1fBat3bV&code=i1WsRn1uB1&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
        OAuth2Message msg = new OAuth2Message("", "", decodeForm(parameters));
        try {
            validator.validateClientIdWithPassword(msg,o2a);
            fail("no clientid");
        } catch (OAuth2ProblemException expected) {
        	assertEquals(OAuth2.Problems.PARAMETER_ABSENT, expected.getProblem());
        	assertEquals("invalid_request", PROBLEM_TO_ERROR_CODE.get(OAuth2.Problems.PARAMETER_ABSENT));
        	assertEquals("client_id", (String) expected.getParameters().get("parameter_name"));
        }
    }
    
    public void testClientIdWithNoPassword() throws Exception {
    	OAuth2Client o2c = new OAuth2Client("https://client.example.com/cb","s6BhdRkqt3","gX1fBat3bV");
    	OAuth2Accessor o2a = new OAuth2Accessor(o2c);
        //validator.checkSingleParameters(new OAuthMessage("", "", OAuth.decodeForm("x=y&x=y")));
        String parameters = "grant_type=authorization_code&client_id=s6BhdRkqt3&code=i1WsRn1uB1&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
        OAuth2Message msg = new OAuth2Message("", "", decodeForm(parameters));
        try {
            validator.validateClientIdWithPassword(msg,o2a);
            fail("no password");
        } catch (OAuth2ProblemException expected) {
        	assertEquals(OAuth2.Problems.PARAMETER_ABSENT, expected.getProblem());
        	assertEquals("invalid_request", PROBLEM_TO_ERROR_CODE.get(OAuth2.Problems.PARAMETER_ABSENT));
        	assertEquals("client_secret", (String) expected.getParameters().get("parameter_name"));
        }
    }

    public void testNoRedirectUri() throws Exception {
    	OAuth2Client o2c = new OAuth2Client("https://client.example.com/cb","s6BhdRkqt3","gX1fBat3bV");
    	OAuth2Accessor o2a = new OAuth2Accessor(o2c);
        //validator.checkSingleParameters(new OAuthMessage("", "", OAuth.decodeForm("x=y&x=y")));
        String parameters = "grant_type=authorization_code&client_id=s6BhdRkqt3&client_secret=gX1fBat3bV&code=i1WsRn1uB1";
        OAuth2Message msg = new OAuth2Message("", "", decodeForm(parameters));
        try {
            validator.validateRedirectUri(msg,o2c);
            fail("no redirect uri");
        } catch (OAuth2ProblemException expected) {
            //assertEquals(OAuth.Problems.PARAMETER_REJECTED, expected.getProblem());
        	assertEquals(OAuth2.Problems.PARAMETER_ABSENT, expected.getProblem());
        	assertEquals("invalid_request", PROBLEM_TO_ERROR_CODE.get(OAuth2.Problems.PARAMETER_ABSENT));
        	assertEquals("redirect_uri", (String) expected.getParameters().get("parameter_name"));
        }
    }
    
    public void testInvalidRedirectUri() throws Exception {
    	OAuth2Client o2c = new OAuth2Client("https://client.example.com/case/invalid","s6BhdRkqt3","gX1fBat3bV");
    	//OAuth2Accessor o2a = new OAuth2Accessor(o2c);
        //validator.checkSingleParameters(new OAuthMessage("", "", OAuth.decodeForm("x=y&x=y")));
        String parameters = "grant_type=authorization_code&client_id=s6BhdRkqt3&client_secret=gX1fBat3bV&code=i1WsRn1uB1&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
        OAuth2Message msg = new OAuth2Message("", "", decodeForm(parameters));
        try {
            validator.validateRedirectUri(msg,o2c);
            fail("invalid redirect uri");
        } catch (OAuth2ProblemException expected) {
        	assertEquals(OAuth2.Problems.REDIRECT_URI_MISMATCH, expected.getProblem());
        	assertEquals("redirect_uri_mismatch", PROBLEM_TO_ERROR_CODE.get(OAuth2.Problems.REDIRECT_URI_MISMATCH));
        }
    }
    
    public void testNoResponseType() throws Exception {
    	//OAuth2Client o2c = new OAuth2Client("https://client.example.com/cb","s6BhdRkqt3","gX1fBat3bV");
    	//OAuth2Accessor o2a = new OAuth2Accessor(o2c);
        //validator.checkSingleParameters(new OAuthMessage("", "", OAuth.decodeForm("x=y&x=y")));
        String parameters = "client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
        OAuth2Message msg = new OAuth2Message("", "", decodeForm(parameters));
        try {
            validator.validateResponseType(msg);
            fail("no respose type");
        } catch (OAuth2ProblemException expected) {
            //assertEquals(OAuth.Problems.PARAMETER_REJECTED, expected.getProblem());
        	assertEquals(OAuth2.Problems.PARAMETER_ABSENT, expected.getProblem());
        	assertEquals("invalid_request", PROBLEM_TO_ERROR_CODE.get(OAuth2.Problems.PARAMETER_ABSENT));
        	assertEquals("response_type", (String) expected.getParameters().get("parameter_name"));
        }
    }
    
    public void testInvalidResponseType() throws Exception {
    	//OAuth2Client o2c = new OAuth2Client("https://client.example.com/case/invalid","s6BhdRkqt3","gX1fBat3bV");
    	//OAuth2Accessor o2a = new OAuth2Accessor(o2c);
        //validator.checkSingleParameters(new OAuthMessage("", "", OAuth.decodeForm("x=y&x=y")));
        String parameters = "response_type=token&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
        OAuth2Message msg = new OAuth2Message("", "", decodeForm(parameters));
        try {
            validator.validateResponseType(msg);
            fail("invalid response type");
        } catch (OAuth2ProblemException expected) {
            //assertEquals(OAuth.Problems.PARAMETER_REJECTED, expected.getProblem());
        	assertEquals(OAuth2.Problems.UNSUPPORTED_RESPONSE_TYPE, expected.getProblem());
        	assertEquals("unsupported_response_type", PROBLEM_TO_ERROR_CODE.get(OAuth2.Problems.UNSUPPORTED_RESPONSE_TYPE));
        }
    }*/
/*    public void testNonceUsed() throws Exception {
        final long currentTime = currentTimeMsec / 1000;
        final String[] values = { null, "",  currentTime + "", (currentTime - 1) + "" };
        // Using the same set of values for all parameters tests that
        // the validator keeps the parameters separate.
        for (String timestamp : values)
            for (String nonce : values)
                for (String consumerKey : values)
                    for (String token : values)
                        if (timestamp == null || nonce == null)
                            try {
                                tryNonce(timestamp, nonce, consumerKey, token);
                                fail("timestamp " + timestamp + ", nonce " + nonce);
                            } catch (OAuthProblemException e) {
                                assertEquals(OAuth.Problems.PARAMETER_ABSENT, e.getProblem());
                            }
                        else if (timestamp.length() > 0)
                            // The consumerKey or token may be absent (null).
                            tryNonce(timestamp, nonce, consumerKey, token);

        for (String timestamp : values)
            for (String nonce : values)
                for (String consumerKey : values)
                    for (String token : values)
                        if (timestamp == null || nonce == null)
                            try {
                                tryNonce(timestamp, nonce, consumerKey, token);
                                fail("timestamp " + timestamp + ", nonce " + nonce);
                            } catch (OAuthProblemException e) {
                                assertEquals(OAuth.Problems.PARAMETER_ABSENT, e.getProblem());
                            }
                        else if (timestamp.length() > 0)
                            try {
                                tryNonce(timestamp, nonce, consumerKey, token);
                                fail("repeated timestamp " + timestamp + ", nonce " + nonce);
                            } catch (OAuthProblemException e) {
                                assertEquals(OAuth.Problems.NONCE_USED, e.getProblem());
                            }
    }
*/
    //private void tryNonce(String timestamp, String nonce, String consumerKey, String token) throws Exception {
    //    OAuthMessage message = new OAuthMessage("", "", null);
    //    addParameter(message, OAuth.OAUTH_TIMESTAMP, timestamp);
    //    addParameter(message, OAuth.OAUTH_NONCE, nonce);
    //    addParameter(message, OAuth.OAUTH_CONSUMER_KEY, consumerKey);
    //    addParameter(message, OAuth.OAUTH_TOKEN, token);
    //    validator.validateTimestampAndNonce(message);
    //}

    //private void addParameter(OAuthMessage message, String name, String value) {
    //    if (value != null)
    //        message.addParameter(name, value);
    //}

    //public void testTimeRange() throws Exception {
    //    final long window = SimpleOAuthValidator.DEFAULT_TIMESTAMP_WINDOW;
    //    tryTime(currentTimeMsec - window - 500); // round up
    //    tryTime(currentTimeMsec + window + 499); // round down
    //    try {
    //        tryTime(currentTimeMsec - window - 501);
    //        fail("validator should have rejected timestamp, but didn't");
    //    } catch (OAuthProblemException expected) {
    //    }
    //    try {
    //        tryTime(currentTimeMsec + window + 500);
    //        fail("validator should have rejected timestamp, but didn't");
    //    } catch (OAuthProblemException expected) {
    //    }
    //}

/*    private void tryTime(long timestamp) throws Exception {
        OAuthMessage msg = new OAuthMessage("", "", OAuth.newList(
                "oauth_timestamp", ((timestamp + 500) / 1000) + "",
                "oauth_nonce", "lsfksdklfjfg"));
        validator.validateTimestampAndNonce(msg);
    }

    public void testVersionRange() throws Exception {
        tryVersion(1.0);
        try {
            tryVersion(0.9);
            fail("validator should have rejected version, but didn't");
        } catch (OAuthProblemException expected) {
        }
        try {
            tryVersion(1.2);
            fail("validator should have rejected version, but didn't");
        } catch (OAuthProblemException expected) {
        }
        try {
            tryVersion(2.0);
            fail("validator should have rejected version, but didn't");
        } catch (OAuthProblemException expected) {
        }
    }

    private void tryVersion(double version) throws Exception {
        OAuthMessage msg = new OAuthMessage("", "", OAuth.newList(
                "oauth_version", version + ""));
        validator.validateVersion(msg);
    }
*/
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
