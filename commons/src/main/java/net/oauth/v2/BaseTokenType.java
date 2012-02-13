package net.oauth.v2;

/**
 * Created by IntelliJ IDEA.
 * User: Yutaka Obuchi
 * Date: 11/12/30
 * Time: 15:05
 * To change this template use File | Settings | File Templates.
 */
public class BaseTokenType {
    private static BaseTokenType ourInstance;

    public synchronized static BaseTokenType getInstance() {
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
                ourInstance = new BaseTokenType();
        }
        return ourInstance;
    }

    public static final String BEARER = "bearer";



    protected BaseTokenType() {
    }

    public synchronized static void addExtension(BaseTokenType baseTokenType) {

        if (baseTokenType == null) {
            // TODO throw Exception
            return;
        }

        if(ourInstance != null && !(ourInstance instanceof BaseTokenType)){
            // TODO throw Exception
            return;
        }

        ourInstance = baseTokenType;
    }
}
