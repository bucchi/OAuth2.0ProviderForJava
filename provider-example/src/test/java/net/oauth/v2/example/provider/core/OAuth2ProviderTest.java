/*
 * Copyright 2010-2012 Yutaka Obuchi
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

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.net.URLDecoder;

import junit.framework.TestCase;

import net.oauth.v2.*;

import net.oauth.v2.example.provider.core.*;
/**
 * @author Yutaka Obuchi
 */
public class OAuth2ProviderTest extends TestCase {

    /*
     * test for loadConsumers() and getClient(OAuth2Message requestMessage)
     */
	public void testLoadConsumers() throws Exception {
		SampleOAuth2Provider.loadConsumers();
		String parameters = "grant_type=authorization_code&client_id=myKey&client_secret=invalid&code=code&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
        OAuth2Message msg = new OAuth2Message("", "", decodeForm(parameters));
    	OAuth2Client o2c = SampleOAuth2Provider.getClient(msg);
        
    	assertEquals("myKey", o2c.clientId);
    	assertEquals("myKey", (String)o2c.getProperty("name"));
    	assertEquals("CookieJar", (String)o2c.getProperty("description")); 
        assertEquals("mySecret", o2c.clientSecret);
        assertEquals("http://localhost/CookieJar/Callback", o2c.redirectUri);
        
    }

    public void testGenerateCode() throws Exception {
        OAuth2Client o2c = new OAuth2Client("https://client.example.com/cb","s6BhdRkqt3","gX1fBat3bV");
        OAuth2Accessor o2a = new OAuth2Accessor(o2c);

        SampleOAuth2Provider.generateCode(o2a);
        assertNotNull(o2a.code);
    }

    public void testGetAccessorByCode() throws Exception {
        OAuth2Client o2c = new OAuth2Client("https://client.example.com/cb","s6BhdRkqt3","gX1fBat3bV");
        OAuth2Accessor o2a = new OAuth2Accessor(o2c);

        SampleOAuth2Provider.generateCode(o2a);
        String parameters = "grant_type=authorization_code&client_id=s6BhdRkqt3&client_secret=invalid&code="+o2a.code+"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
        OAuth2Message msg = new OAuth2Message("", "", decodeForm(parameters));

        OAuth2Accessor cachedAccessor = SampleOAuth2Provider.getAccessorByCode(msg);
        assertSame(o2a, cachedAccessor);
    }

    public void testGenerateAccessAndRefreshToken() throws Exception {
        OAuth2Client o2c = new OAuth2Client("https://client.example.com/cb","s6BhdRkqt3","gX1fBat3bV");
        o2c.setProperty("name",o2c.clientId);
        OAuth2Accessor o2a = new OAuth2Accessor(o2c);
        SampleOAuth2Provider.generateCode(o2a);
        SampleOAuth2Provider.generateAccessAndRefreshToken(o2a);
        String parameters = "grant_type=authorization_code&client_id=s6BhdRkqt3&client_secret=invalid&code="+o2a.code+"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
        OAuth2Message msg = new OAuth2Message("", "", decodeForm(parameters));

        OAuth2Accessor cachedAccessor = SampleOAuth2Provider.getAccessorByCode(msg);
        assertSame(o2a, cachedAccessor);
        assertNotNull(o2a.accessToken);
        assertEquals(o2c.clientId, cachedAccessor.client.clientId);

    }

	public void testMarkAsAuthorized() throws Exception {
    	OAuth2Client o2c = new OAuth2Client("https://client.example.com/cb","s6BhdRkqt3","gX1fBat3bV");
    	o2c.setProperty("name",o2c.clientId);
    	OAuth2Accessor o2a = new OAuth2Accessor(o2c);
    	SampleOAuth2Provider.generateCode(o2a);
        SampleOAuth2Provider.generateAccessAndRefreshToken(o2a);
        SampleOAuth2Provider.markAsAuthorized(o2a,"yutaka");
        
        String parameters = "grant_type=authorization_code&client_id=s6BhdRkqt3&client_secret=invalid&code="+o2a.code+"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
        OAuth2Message msg = new OAuth2Message("", "", decodeForm(parameters));
        
        OAuth2Accessor cachedAccessor = SampleOAuth2Provider.getAccessorByCode(msg);
        assertSame(o2a, cachedAccessor);
        assertEquals(o2c.clientId, cachedAccessor.client.clientId);
        assertEquals("yutaka", (String) cachedAccessor.getProperty("user"));
        assertTrue((Boolean) cachedAccessor.getProperty("authorized"));
    	
    }

    public void testGetAccessorByRefreshToken() throws Exception {
        OAuth2Client o2c = new OAuth2Client("https://client.example.com/cb","s6BhdRkqt3","gX1fBat3bV");
        OAuth2Accessor o2a = new OAuth2Accessor(o2c);

        SampleOAuth2Provider.generateCode(o2a);
        SampleOAuth2Provider.generateAccessAndRefreshToken(o2a);
        String parameters = "refresh_token="+o2a.refreshToken+"&client_id=s6BhdRkqt3&client_secret=gX1fBat3bV&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
        OAuth2Message msg = new OAuth2Message("", "", decodeForm(parameters));

        OAuth2Accessor cachedAccessor = SampleOAuth2Provider.getAccessorByRefreshToken(msg);
        assertSame(o2a, cachedAccessor);
        assertNotNull(o2a.accessToken);
        assertEquals(o2c.clientId, cachedAccessor.client.clientId);
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
