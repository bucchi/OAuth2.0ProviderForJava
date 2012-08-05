/*
 * Copyright 2011 Yutaka Obuchi
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

package net.oauth.v2;

import java.util.List;
import java.util.ArrayList;
import java.net.URLDecoder;

import junit.framework.TestCase;

public class OAuth2Test extends TestCase {

    private static final String[] STANDARD =
    // label, input, expected result
    { "ALPHA", "abcABC", "abcABC" //
            , "DIGIT", "123", "123" //
            , "unreserved", "-._~", "-._~" //
            , "percent", "%", "%25" //
            , "plus", "+", "%2B" //
            , "not unreserved", "&=*", "%26%3D%2A" //
            , "LF", "\n", "%0A" //
            , "SP", " ", "%20" //
            , "DEL", "\u007F", "%7F" //
            , "Latin", "\u0080", "%C2%80" //
            , "CJK", "\u3001", "%E3%80%81" //
    };

    private static final String[] FLEXIBLE =
    // label, input, expected result
    { "SP", " ", "+" //
            , "slash", "/", "%2F" //
            , "not unreserved", "&=*", "%26%3D%2A" //
            , "lower case hex", "/=*\u3001", "%2f%3d%2a%e3%80%81" //
    };
    
    private static final String[] PARAMETERS =
            // label, input, expected result
            { "https://client.example.com/cb", "code=i1WsRn1uB1&expires_in=3600"//
                    , "https://client.example.com/cb?code=i1WsRn1uB1&expires_in=3600" //
            };

    private static final String[] PARAMETERS4FRAGMENT =
            // label, input, expected result
            { "https://client.example.com/cb", "access_token=2YotnFZFEjr1zCsicMWpAA&state=xyz&token_type=example&expires_in=3600"//
                    , "https://client.example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA&state=xyz&token_type=example&expires_in=3600" //
            };

    // add callback URL
    
    public void testAddParameters() {
        String base = PARAMETERS[0];
        List<OAuth2.Parameter> parameters = decodeForm(PARAMETERS[1]);
        String result1 = null;
        try{
        	result1 = OAuth2.addParameters(base,parameters);
        }catch(Exception e){
        	
        }
        assertEquals("list Parameter", PARAMETERS[2],result1);
        
        String result2 = null;
        try{
        	String key1 = ((OAuth2.Parameter)parameters.get(0)).getKey();
        	String value1 = ((OAuth2.Parameter)parameters.get(0)).getValue();
        	String key2 = ((OAuth2.Parameter)parameters.get(1)).getKey();
        	String value2 = ((OAuth2.Parameter)parameters.get(1)).getValue();
        	result2 = OAuth2.addParameters(base,key1,value1,key2,value2);
        }catch(Exception e){
        	
        }
        assertEquals("String Parameter", PARAMETERS[2],result2);
    }

    public void testAddParametersAsFragment() {
        String base = PARAMETERS4FRAGMENT[0];
        List<OAuth2.Parameter> parameters = decodeForm(PARAMETERS4FRAGMENT[1]);
        String result1 = null;
        try{
            result1 = OAuth2.addParametersAsFragment(base,parameters);
        }catch(Exception e){

        }
        assertEquals("list Parameter", PARAMETERS4FRAGMENT[2],result1);

        String result2 = null;
        try{
            String key1 = ((OAuth2.Parameter)parameters.get(0)).getKey();
            String value1 = ((OAuth2.Parameter)parameters.get(0)).getValue();
            String key2 = ((OAuth2.Parameter)parameters.get(1)).getKey();
            String value2 = ((OAuth2.Parameter)parameters.get(1)).getValue();
            String key3 = ((OAuth2.Parameter)parameters.get(2)).getKey();
            String value3 = ((OAuth2.Parameter)parameters.get(2)).getValue();
            String key4 = ((OAuth2.Parameter)parameters.get(3)).getKey();
            String value4 = ((OAuth2.Parameter)parameters.get(3)).getValue();
            result2 = OAuth2.addParametersAsFragment(base,key1,value1,key2,value2,key3,value3,key4,value4);
        }catch(Exception e){

        }
        assertEquals("String Parameter", PARAMETERS4FRAGMENT[2],result2);
    }


    public void testEncode() {
        StringBuffer errors = new StringBuffer();
        for (int c = 0; c < STANDARD.length; c += 3) {
            String label = STANDARD[c];
            String input = STANDARD[c + 1];
            String expected = STANDARD[c + 2];
            String actual = OAuth2.percentEncode(input);
            if (!expected.equals(actual)) {
                if (errors.length() > 0)
                    errors.append(", ");
                errors.append(label).append(" ").append(actual);
            }
        }
        if (errors.length() > 0)
            fail(errors.toString());
    }

    public void testDecodeStandard() {
        testDecode(STANDARD);
    }

    public void testDecodeFlexible() {
        testDecode(FLEXIBLE);
    }

    public void testDecodeFormCornerCases() throws Exception {

	List<OAuth2.Parameter> msgParams = decodeForm("foo=bar");
	assertEquals(1, msgParams.size());
	assertEquals("foo", msgParams.get(0).getKey());
	assertEquals("bar", msgParams.get(0).getValue());

	msgParams = decodeForm("foo");
	assertEquals(1, msgParams.size());
	assertEquals("foo", msgParams.get(0).getKey());
	assertNull(msgParams.get(0).getValue());

	msgParams = decodeForm(null);
	assertNotNull(msgParams);
	assertEquals(0, msgParams.size());

	msgParams = decodeForm("");
	assertNotNull(msgParams);
	assertEquals(0, msgParams.size());

	msgParams = decodeForm("   ");
	assertEquals(1, msgParams.size());
	assertEquals("   ", msgParams.get(0).getKey());
	assertNull(msgParams.get(0).getValue());

	msgParams = decodeForm("=");
	assertEquals(1, msgParams.size());
	assertEquals("", msgParams.get(0).getKey());
	assertEquals("", msgParams.get(0).getValue());

	msgParams = decodeForm("= ");
	assertEquals(1, msgParams.size());
	assertEquals("", msgParams.get(0).getKey());
	assertEquals(" ", msgParams.get(0).getValue());

	msgParams = decodeForm(" =");
	assertEquals(1, msgParams.size());
	assertEquals(" ", msgParams.get(0).getKey());
	assertEquals("", msgParams.get(0).getValue());
    }

    private static void testDecode(String[] cases) {
        StringBuffer errors = new StringBuffer();
        for (int c = 0; c < cases.length; c += 3) {
            String label = cases[c];
            String input = cases[c + 2];
            String expected = cases[c + 1];
            String actual = OAuth2.decodePercent(input);
            if (!expected.equals(actual)) {
                if (errors.length() > 0)
                    errors.append(", ");
                errors.append(label).append(" ").append(actual);
            }
        }
        if (errors.length() > 0)
            fail(errors.toString());
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
