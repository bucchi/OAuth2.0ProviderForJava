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

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import junit.framework.TestCase;

import net.oauth.v2.*;
import net.oauth.v2.example.provider.core.*;
import net.oauth.v2.example.provider.servlets.AuthorizationServlet2;

import org.apache.jasper.servlet.JspServlet;
import org.mortbay.jetty.testing.ServletTester;
import org.mortbay.jetty.testing.HttpTester;
/**
 * @author Yutaka Obuchi
 */
public class AuthorizationServlet2Test extends TestCase {


    //@Override
    //protected void setUp() throws Exception {
    //    currentTimeMsec = (System.currentTimeMillis() / 1000) * 1000;
    //    validator = new SimpleOAuth2Validator() {
    //        @Override
    //        protected long currentTimeMsec() {return currentTimeMsec;}
    //    };
    //}

    /*
     * Authorization Code Grant
     */
    public void testDoGet1() throws Exception {

        ServletTester tester=new ServletTester();
        tester.setContextPath("/test");
        tester.addServlet(AuthorizationServlet2.class, "/authorize");
        tester.setResourceBase("./web");
        tester.addServlet(JspServlet.class, "*.jsp");
        tester.start();

        String queryParameter = "response_type=code&client_id=myKey&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%2FCookieJar%2FCallback";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("GET");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/authorize"+"?"+queryParameter);
        request.setVersion("HTTP/1.1");

        response.parse(tester.getResponses(request.generate()));

        assertEquals(200,response.getStatus());
        assertTrue(response.getContent().contains("<h3>\"CookieJar\" is trying to access your information.</h3>"));
        assertTrue(response.getContent().contains("<form name=\"authZForm\" action=\"auth\" method=\"POST\">\n" +
                "        <input type=\"text\" name=\"userId\" value=\"\" size=\"20\" /><br>\n" +
                "        <input type=\"hidden\" name=\"redirect_uri\" value=\"http://localhost/CookieJar/Callback\"/>\n" +
                "        <input type=\"hidden\" name=\"client_id\" value=\"myKey\"/>        \n" +
                "        <input type=\"submit\" name=\"Authorize\" value=\"Authorize\"/>\n" +
                "    </form>"));

    }

    /*
     * Error Case: unknown client id with error=invalid_client
     */
    public void testDoGet2() throws Exception {

        ServletTester tester=new ServletTester();
        tester.setContextPath("/test");
        tester.addServlet(AuthorizationServlet2.class, "/authorize");
        tester.setResourceBase("./web");
        tester.addServlet(JspServlet.class, "*.jsp");
        tester.start();

        String queryParameter = "response_type=code&client_id=invalidKey&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%2FCookieJar%2FCallback";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("GET");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/authorize"+"?"+queryParameter);
        request.setVersion("HTTP/1.1");

        response.parse(tester.getResponses(request.generate()));

        assertEquals(302,response.getStatus());
        assertEquals("http://localhost/CookieJar/Callback?error=invalid_client&state=xyz",response.getHeader("location"));

    }
    /*
     * implicit grant
     */
    public void testDoGet3() throws Exception {

        ServletTester tester=new ServletTester();
        tester.setContextPath("/test");
        tester.addServlet(AuthorizationServlet2.class, "/authorize");
        tester.setResourceBase("./web");
        tester.addServlet(JspServlet.class, "*.jsp");
        tester.start();

        String queryParameter = "response_type=token&client_id=myKey&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%2FCookieJar%2FCallback";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("GET");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/authorize"+"?"+queryParameter);
        request.setVersion("HTTP/1.1");

        response.parse(tester.getResponses(request.generate()));

        assertEquals(200,response.getStatus());
        assertTrue(response.getContent().contains("<h3>\"CookieJar\" is trying to access your information.</h3>"));
        assertTrue(response.getContent().contains("<form name=\"authZForm\" action=\"auth\" method=\"POST\">\n" +
                "        <input type=\"text\" name=\"userId\" value=\"\" size=\"20\" /><br>\n" +
                "        <input type=\"hidden\" name=\"redirect_uri\" value=\"http://localhost/CookieJar/Callback\"/>\n" +
                "        <input type=\"hidden\" name=\"client_id\" value=\"myKey\"/>        \n" +
                "        <input type=\"submit\" name=\"Authorize\" value=\"Authorize\"/>\n" +
                "    </form>"));


    }
    /*
     * implicit grant2
     */
    public void testDoGet4() throws Exception {

        ServletTester tester=new ServletTester();
        tester.setContextPath("/test");
        tester.addServlet(AuthorizationServlet2.class, "/authorize");
        tester.setResourceBase("./web");
        tester.addServlet(JspServlet.class, "*.jsp");
        tester.start();

        String queryParameter = "response_type=token&client_id=myKey&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%2FCookieJar%2FCallback";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("GET");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/authorize"+"?"+queryParameter);
        request.setVersion("HTTP/1.1");

        response.parse(tester.getResponses(request.generate()));

        assertEquals(200,response.getStatus());
        assertTrue(response.getContent().contains("<h3>\"CookieJar\" is trying to access your information.</h3>"));
        assertTrue(response.getContent().contains("<form name=\"authZForm\" action=\"auth\" method=\"POST\">\n" +
                "        <input type=\"text\" name=\"userId\" value=\"\" size=\"20\" /><br>\n" +
                "        <input type=\"hidden\" name=\"redirect_uri\" value=\"http://localhost/CookieJar/Callback\"/>\n" +
                "        <input type=\"hidden\" name=\"client_id\" value=\"myKey\"/>        \n" +
                "        <input type=\"submit\" name=\"Authorize\" value=\"Authorize\"/>\n" +
                "    </form>"));


        request = new HttpTester();
        response = new HttpTester();

        String postParameter = "userId=yutaka&response_type=token&client_id=myKey&state=xyz"+
                "&redirect_uri=http%3A%2F%2Flocalhost%2FCookieJar%2FCallback";

        request.setMethod("POST");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/authorize");
        request.setVersion("HTTP/1.1");
        request.setHeader("Content-Type","application/x-www-form-urlencoded;charset=UTF-8");
        request.setContent(postParameter);

        response.parse(tester.getResponses(request.generate()));

        assertEquals(302,response.getStatus());
        Pattern pattern = Pattern.compile("http://localhost/CookieJar/Callback#access_token=.+&token_type=bearer&expires_in=3600&state=xyz");
        Matcher matcher = pattern.matcher(response.getHeader("Location"));
        assertTrue(matcher.matches());

    }

    public void testDoGet5() throws Exception {

        ServletTester tester=new ServletTester();
        tester.setContextPath("/test");
        tester.addServlet(AuthorizationServlet2.class, "/authorize");
        tester.setResourceBase("./web");
        tester.addServlet(JspServlet.class, "*.jsp");
        tester.start();

        String queryParameter = "response_type=token&client_id=invalidKey&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%2FCookieJar%2FCallback";
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setMethod("GET");
        request.setHeader("Host","server.example.com");
        request.setURI("/test/authorize"+"?"+queryParameter);
        request.setVersion("HTTP/1.1");

        response.parse(tester.getResponses(request.generate()));

        assertEquals(302,response.getStatus());
        assertEquals("http://localhost/CookieJar/Callback?error=invalid_client&state=xyz",response.getHeader("location"));

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
