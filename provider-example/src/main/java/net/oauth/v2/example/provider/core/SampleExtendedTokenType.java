package net.oauth.v2.example.provider.core;

import net.oauth.v2.BaseTokenType;

/**
 * Created by IntelliJ IDEA.
 * User: yutaka
 * Date: 12/02/13
 * Time: 6:08
 * To change this template use File | Settings | File Templates.
 */
public class SampleExtendedTokenType extends BaseTokenType {

    public static final String MAC = "mac";

    static {
        addExtension(new SampleExtendedTokenType());
    }

    protected SampleExtendedTokenType() {
    }
}
