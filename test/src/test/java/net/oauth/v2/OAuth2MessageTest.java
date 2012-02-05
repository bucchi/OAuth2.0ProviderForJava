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

package net.oauth.v2;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.net.URLDecoder;
import junit.framework.TestCase;

//import net.oauth.v2.OAuth2.Parameter;

public class OAuth2MessageTest extends TestCase
{
    private static final String[][] OAUTH_PARAMETERS =
    // label, inputs, expected result
    { { "Prameter check", "grant_type=authorization_code&client_id=s6BhdRkqt3&code=i1WsRn1uB1&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb","authorization_code","s6BhdRkqt3","i1WsRn1uB1","https://client.example.com/cb"} 
    };
    
    private static final String[] HEADERS =
        // label, inputs, expected result
        
        { "Content-Type", "application/x-www-form-urlencoded", "Authorization","OAuth vF9dft4qmT"};
    
    public void testGetParameter() throws Exception
    {
        for (String[] testCase : OAUTH_PARAMETERS) {
            String label = testCase[0];
            //String realm = testCase[1];
            List<OAuth2.Parameter> parameters = decodeForm(testCase[1]);
            String expectedGrantType = testCase[2];
            String expectedClientId = testCase[3];
            //String expectedSecret = testCase[5];
            String expectedCode = testCase[4];
            String expectedRedirectURI = testCase[5];
            OAuth2Message message = new OAuth2Message("", "", parameters);
            assertEquals(label, expectedGrantType, message.getParameter(OAuth2.GRANT_TYPE));
            assertEquals(label, expectedClientId, message.getClientId());
            //assertEquals(label, expectedSecret, message.getParameter(OAuth2.CLIENT_SECRET));
            assertEquals(label, expectedCode, message.getCode());
            assertEquals(label, expectedRedirectURI, message.getParameter(OAuth2.REDIRECT_URI));
        }
    }
    
    public void testGetHeader() throws Exception
    {
    	for (String[] testCase : OAUTH_PARAMETERS) {
            List<OAuth2.Parameter> parameters = decodeForm(testCase[2]);
    		OAuth2Message message = new OAuth2Message("", "", parameters);
    		List<Map.Entry<String, String>> headers = message.getHeaders();
    		headers.add(new OAuth2.Parameter(HEADERS[0], HEADERS[1]));
    		headers.add(new OAuth2.Parameter(HEADERS[2], HEADERS[3]));
            assertEquals("Header check", HEADERS[1], message.getHeader(HEADERS[0]));
            assertEquals("Header check", HEADERS[3], message.getHeader(HEADERS[2]));
        }
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
