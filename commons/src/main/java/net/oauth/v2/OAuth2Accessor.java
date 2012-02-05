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
package net.oauth.v2;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Properties of one User of an OAuthConsumer. Properties may be added freely,
 * e.g. to support extensions.
 * 
 * @author John Kristian
 */
public class OAuth2Accessor implements Cloneable, Serializable {

    private static final long serialVersionUID = 5590788443138352999L;
    
    public final OAuth2Client client;
    public String tokenType;
    public String accessToken;
    public String code;
    public String refreshToken;
    public String expires_in;
    public String scope;
    public String state;

    
    public OAuth2Accessor(OAuth2Client client) {
        this.client = client;
        this.code = null;
        this.accessToken = null;
        this.refreshToken = null;
        this.scope = null;
        this.state = null;
    }

    private final Map<String, Object> properties = new HashMap<String, Object>();

    @Override
    public OAuth2Accessor clone() {
        try {
            return (OAuth2Accessor) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    public Object getProperty(String name) {
        return properties.get(name);
    }

    public void setProperty(String name, Object value) {
        properties.put(name, value);
    }

    /**
     * Construct a request message containing the given parameters but no body.
     * Don't send the message, merely construct it. The caller will ordinarily
     * send it, for example by calling OAuthClient.invoke or access.
     * 
     * @param method
     *            the HTTP request method. If this is null, use the default
     *            method; that is getProperty("httpMethod") or (if that's null)
     *            consumer.getProperty("httpMethod") or (if that's null)
     *            OAuthMessage.GET.
     */
    //public OAuthMessage newRequestMessage(String method, String url, Collection<? extends Map.Entry> parameters,
    //        InputStream body) throws OAuthException, IOException, URISyntaxException {
    //    if (method == null) {
    //        method = (String) this.getProperty("httpMethod");
    //        if (method == null) {
    //            method = (String) this.consumer.getProperty("httpMethod");
    //            if (method == null) {
    //                method = OAuthMessage.GET;
    //            }
    //        }
    //    }
    //    OAuthMessage message = new OAuthMessage(method, url, parameters, body);
    //    message.addRequiredParameters(this);
    //    return message;
    //}

    //public OAuthMessage newRequestMessage(String method, String url, Collection<? extends Map.Entry> parameters)
    //        throws OAuthException, IOException, URISyntaxException {
    //    return newRequestMessage(method, url, parameters, null);
    //}

}
