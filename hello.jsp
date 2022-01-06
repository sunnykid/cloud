<%@ page contentType="text/html;charset=utf-8"%>
<html>
    <body>
        <% out.println("hello jsp");%>
            <%String a = "hello";%>
        <%=a%><br/>
        //<%=a%>는 표현식이며, out.println()과 동일하게 사용 할 수 있다.<br/>
        <%
            for(int i = 0; i <= 10; i++){
                out.println("Hello World" + i + "<br/>");
            }
        %>
        // 위의 JSP로 구현된 for문은 아래와도 같이 사용 할 수 있다.<br/>
        <% for ( int j = 0; j <= 10; j++){%>
            <%=j%><br/>
        <%}%>
    </body>
</html>
