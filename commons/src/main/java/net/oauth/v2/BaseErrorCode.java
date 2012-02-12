package net.oauth.v2;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * User: Yutaka Obuchi
 * Date: 11/12/30
 * Time: 15:05
 * To change this template use File | Settings | File Templates.
 */
public class BaseErrorCode {
    private static BaseErrorCode ourInstance;

    public synchronized static BaseErrorCode getInstance() {
        if (ourInstance == null) {
            // TODO make it possible to specify an extened class with config class
            //String className = "test";
            //if (className != null && !className.equals("")) {
            //    try {
            //        ourInstance = (BaseResponseType) Class.forName(className).newInstance();
            //    } catch (Exception e) {
            //TODO log
            //    }
            //}
            //if (ourInstance == null)
                ourInstance = new BaseErrorCode();
        }
        return ourInstance;
    }

    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
    public static final String REDIRECT_URI_MISMATCH = "redirect_uri_mismatch";
    public static final String ACCESS_DENIED = "access_denied";
    public static final String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    public static final String INVALID_SCOPE = "invalid_scope";
    public static final String INVALID_GRANT = "invalid_grant";
    public static final String INVALID_TOKEN = "invalid_token";

    private BaseErrorCode() {
    }

    public synchronized static void addExtension(BaseErrorCode baseErrorCode) {

        if (baseErrorCode == null) {
            // TODO throw Exception
            return;
        }

        if(ourInstance != null && !(ourInstance instanceof BaseErrorCode)){
            // TODO throw Exception
            return;
        }

        ourInstance = baseErrorCode;
    }

    public static final Map<String, Integer> TO_HTTP_CODE = mapToHttpCode();

    private static Map<String, Integer> mapToHttpCode() {
        Integer badRequest = new Integer(400);
        Integer unauthorized = new Integer(401);
        Integer serviceUnavailable = new Integer(503);
        Map<String, Integer> map = new HashMap<String, Integer>();

        map.put(UNAUTHORIZED_CLIENT, unauthorized);
        map.put(INVALID_CLIENT, unauthorized);
        map.put(INVALID_REQUEST, badRequest);
        map.put(INVALID_TOKEN, unauthorized);

        return Collections.unmodifiableMap(map);
    }
}
