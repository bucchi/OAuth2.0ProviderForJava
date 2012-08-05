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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import junit.framework.TestCase;
import net.oauth.v2.*;
import net.oauth.v2.example.provider.core.SampleOAuth2Provider;

import org.mortbay.jetty.testing.ServletTester;
import org.mortbay.jetty.testing.HttpTester;

import org.apache.commons.codec.binary.Base64;

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
     * Client Authentication with basic auth
     */
    public void testDoPost3() throws Exception {
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
                "&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%2FCookieJar%2FCallback";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("POST");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/token");
        request.setVersion("HTTP/1.1");
        request.setHeader("Content-Type","application/x-www-form-urlencoded;charset=UTF-8");
        String userPass = new String(Base64.encodeBase64("myKey:mySecret".getBytes()), "UTF-8");
        request.setHeader("Authorization", "Basic "+userPass);
        request.setContent(postParameter);

        response.parse(tester.getResponses(request.generate()));

        assertEquals(200,response.getStatus());
        assertEquals("{\"access_token\":\"" + o2a.accessToken +
                "\",\"token_type\":\"" + o2a.tokenType +
                "\",\"expires_in\":\"3600\",\"refresh_token\":\"" + o2a.refreshToken +
                "\"}",response.getContent());

    }

    /*
     * Client Basic Authentication Error Case : invalid client id
     */
    public void testDoPost4() throws Exception {
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
                "&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%2FCookieJar%2FCallback";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("POST");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/token");
        request.setVersion("HTTP/1.1");
        request.setHeader("Content-Type","application/x-www-form-urlencoded;charset=UTF-8");
        String userPass = new String(Base64.encodeBase64("invalidKey:mySecret".getBytes()), "UTF-8");
        request.setHeader("Authorization", "Basic "+userPass);
        request.setContent(postParameter);

        response.parse(tester.getResponses(request.generate()));

        assertEquals(401,response.getStatus());
        assertEquals("{\"error\":\"invalid_client\"}",response.getContent());

    }

    /*
     * Client Basic Authentication Error Case : invalid password id
     */
    public void testDoPost5() throws Exception {
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
                "&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%2FCookieJar%2FCallback";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("POST");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/token");
        request.setVersion("HTTP/1.1");
        request.setHeader("Content-Type","application/x-www-form-urlencoded;charset=UTF-8");
        String userPass = new String(Base64.encodeBase64("myKey:invalidSecret".getBytes()), "UTF-8");
        request.setHeader("Authorization", "Basic "+userPass);
        request.setContent(postParameter);

        response.parse(tester.getResponses(request.generate()));

        assertEquals(401,response.getStatus());
        assertEquals("{\"error\":\"invalid_client\"}",response.getContent());

    }

    /*
     * Client Basic Authentication Error Case : invalid format(myKey+mySecret)
     */
    public void testDoPost6() throws Exception {
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
                "&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%2FCookieJar%2FCallback";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("POST");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/token");
        request.setVersion("HTTP/1.1");
        request.setHeader("Content-Type","application/x-www-form-urlencoded;charset=UTF-8");
        String userPass = new String(Base64.encodeBase64("myKey+mySecret".getBytes()), "UTF-8");
        request.setHeader("Authorization", "Basic "+userPass);
        request.setContent(postParameter);

        response.parse(tester.getResponses(request.generate()));

        assertEquals(401,response.getStatus());
        assertEquals("{\"error\":\"invalid_client\"}",response.getContent());

    }

    /*
     * Client Password grant
     */
    public void testDoPost7() throws Exception {

        try{
        ServletTester tester=new ServletTester();
        tester.setContextPath("/test");
        tester.addServlet(AccessTokenServlet2.class, "/token");
        tester.start();

        String postParameter = "grant_type=password&username=yutaka&password=obuchi";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("POST");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/token");
        request.setVersion("HTTP/1.1");
        request.setHeader("Content-Type","application/x-www-form-urlencoded;charset=UTF-8");
        String userPass = new String(Base64.encodeBase64("myKey:mySecret".getBytes()), "UTF-8");
        request.setHeader("Authorization", "Basic "+userPass);
        request.setContent(postParameter);

        response.parse(tester.getResponses(request.generate()));
        System.out.println("yutaka"+response.getContent());
        assertEquals(200,response.getStatus());
        Pattern pattern = Pattern.compile("\\{\"access_token\":\".+\",\"token_type\":\"bearer\",\"expires_in\":\"3600\",\"refresh_token\":\".+\"\\}");
        Matcher matcher = pattern.matcher(response.getContent());
        assertTrue(matcher.matches());
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void testDoPost8() throws Exception {


        ServletTester tester=new ServletTester();
        tester.setContextPath("/test");
        tester.addServlet(AccessTokenServlet2.class, "/token");
        tester.start();

        String postParameter = "grant_type=password&username=invalid&obuchi";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("POST");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/token");
        request.setVersion("HTTP/1.1");
        request.setHeader("Content-Type","application/x-www-form-urlencoded;charset=UTF-8");
        String userPass = new String(Base64.encodeBase64("myKey:invalidSecret".getBytes()), "UTF-8");
        request.setHeader("Authorization", "Basic "+userPass);
        request.setContent(postParameter);

        response.parse(tester.getResponses(request.generate()));

        assertEquals(401,response.getStatus());
        assertEquals("{\"error\":\"invalid_client\"}",response.getContent());

    }

    /*
     * Client Credentials grant
     */
    public void testDoPost9() throws Exception {


        ServletTester tester=new ServletTester();
        tester.setContextPath("/test");
        tester.addServlet(AccessTokenServlet2.class, "/token");
        tester.start();

        String postParameter = "grant_type=client_credentials";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("POST");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/token");
        request.setVersion("HTTP/1.1");
        request.setHeader("Content-Type","application/x-www-form-urlencoded;charset=UTF-8");
        String userPass = new String(Base64.encodeBase64("myKey:mySecret".getBytes()), "UTF-8");
        request.setHeader("Authorization", "Basic "+userPass);
        request.setContent(postParameter);

        response.parse(tester.getResponses(request.generate()));

        assertEquals(200,response.getStatus());
        Pattern pattern = Pattern.compile("\\{\"access_token\":\".+\",\"token_type\":\"bearer\",\"expires_in\":\"3600\"\\}");
        Matcher matcher = pattern.matcher(response.getContent());
        assertTrue(matcher.matches());

    }

    public void testDoPost10() throws Exception {


        ServletTester tester=new ServletTester();
        tester.setContextPath("/test");
        tester.addServlet(AccessTokenServlet2.class, "/token");
        tester.start();

        String postParameter = "grant_type=client_credentials";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("POST");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/token");
        request.setVersion("HTTP/1.1");
        request.setHeader("Content-Type","application/x-www-form-urlencoded;charset=UTF-8");
        String userPass = new String(Base64.encodeBase64("myKey:invalidSecret".getBytes()), "UTF-8");
        request.setHeader("Authorization", "Basic "+userPass);
        request.setContent(postParameter);

        response.parse(tester.getResponses(request.generate()));

        assertEquals(401,response.getStatus());
        assertEquals("{\"error\":\"invalid_client\"}",response.getContent());

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
