package net.oauth.v2;

/**
 * Created by IntelliJ IDEA.
 * User: yutaka
 * Date: 11/12/30
 * Time: 15:05
 * To change this template use File | Settings | File Templates.
 */
public class BaseGrantType {
    private static BaseGrantType ourInstance;

    public synchronized static BaseGrantType getInstance() {
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
                ourInstance = new BaseGrantType();
        }
        return ourInstance;
    }

    public static final String AUTHORIZATION_CODE = "authorization_code";
    public static final String PASSWORD = "password";
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String NONE = "none";

    private BaseGrantType() {
    }

    public synchronized static void addExtension(BaseGrantType baseGrantType) {

        if (baseGrantType == null) {
            // TODO throw Exception
            return;
        }

        if(ourInstance != null && !(ourInstance instanceof BaseGrantType)){
            // TODO throw Exception
            return;
        }

        ourInstance = baseGrantType;
    }
}
