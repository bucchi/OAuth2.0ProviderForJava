/*
 * Copyright 2012 Yutaka Obuchi
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

import junit.framework.TestCase;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;

import net.oauth.v2.BaseTokenType;

/**
 * @author Yutaka Obuchi
 */
public class SampleExtendedTokenTypeTest extends TestCase {

	public void testGetInstance() {
        try{

            Class clazz = Class.forName("net.oauth.v2.example.provider.core.SampleExtendedTokenType");
            SampleExtendedTokenType tokenType = (SampleExtendedTokenType) BaseTokenType.getInstance();

            assertEquals(tokenType.MAC,"mac");
            assertEquals(tokenType.BEARER,"bearer");
        }catch (Exception e){
            fail();
        }
    }

}
