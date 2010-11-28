<%@page contentType="text/html"%>
<%@page pageEncoding="UTF-8"%>
<%
    String client_id = (String)request.getAttribute("CLIE_ID");
    String appDesc = (String)request.getAttribute("CLIE_DESC");
    //String response_type = (String)request.getAttribute("RESPONSE_TYPE");
    String redirect_uri = (String)request.getAttribute("REDIRECT_URI");
    if(redirect_uri == null)
        redirect_uri = "";
    
%>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Your Friendly OAuth Provider</title>
    </head>
    <body>
        <jsp:include page="banner.jsp"/>
        
    <h3>"<%=appDesc%>" is trying to access your information.</h3>
    
    Enter the userId you want to be known as:
    <form name="authZForm" action="auth" method="POST">
        <input type="text" name="userId" value="" size="20" /><br>
        <input type="hidden" name="redirect_uri" value="<%= redirect_uri %>"/>
        <input type="hidden" name="client_id" value="<%= client_id %>"/>        
        <input type="submit" name="Authorize" value="Authorize"/>
    </form>
    
    </body>
</html>
