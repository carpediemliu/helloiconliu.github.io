---
layout:     post
title:      简单实现同名域下单点登录
subtitle:   分布式下的Session共享
date:       2018-03-22
author:     vito
header-img: img/post-bg-e2e-ux.jpg
catalog: true
tags:
    - 分布式
---
** 大概的流程如下 **  
![hash](/img/sso-service.png)


### 一、配置web.xml
```
/webapp/WEB-INF/web.xml
<!-- springMVC前置控制器的配置 -->
<servlet>
<servlet-name>mvc-dispatcher</servlet-name>
<servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
  <!-- springMVC配置文件 -->
<init-param>
<param-name>contextConfigLocation</param-name>
<param-value>/WEB-INF/config/mvc-dispatcher-servlet.xml</param-value>
</init-param>
<load-on-startup>1</load-on-startup>
</servlet>
<!-- 拦截URL中包含[/]的请求 -->
 <servlet-mapping>
<servlet-name>mvc-dispatcher</servlet-name>
<url-pattern>/</url-pattern>
</servlet-mapping>
```

### 二、SpringMVC配置文件
```
/WEB-INF/config/springmvc.xml
......
<mvc:interceptors>
<!-- permission check -->
<mvc:interceptor>
<!-- 需拦截的地址 -->
<!-- 一级目录 -->
<mvc:mapping path="/*.do"/>
<mvc:mapping path="/*.ajax"/>
<mvc:mapping path="/*.htm"/>
<mvc:mapping path="/*.html"/>
<bean/>
</mvc:interceptor>
</mvc:interceptors>
......
```

### 三、自定义拦截器
```
SessionCheckInterceptor.java
public class SessionCheckInterceptor extends AbstractController implements HandlerInterceptor {

private static Logger logger = Logger.getLogger(SessionCheckInterceptor.class);

    @Override
    public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object handler) throws Exception {
        // 取得用户登录Session
        UserLoginSession userLoginSession = getUserLoginSession(req);
        // 如果用户登录Session为空，或者userId的值为空或者userName的值为空
        if (userLoginSession == null || "".equals(userLoginSession.getUserId()) || "".equals(userLoginSession.getUserName())) {
            // 异步请求的场合
            if (req.getHeader("x-requested-with") != null &&
                    req.getHeader("x-requested-with").equalsIgnoreCase("XMLHttpRequest")) {
                res.setHeader("sessionstatus", "sessionTimeOut");
                PrintWriter wirter = res.getWriter();

                // 强制将缓冲区的数据输出
                wirter.flush();
                return false;
            } else {
            // 同步请求的场合
                String path = getPathUrl(req);
                logger.info("Interceptor中返回false");
                // 返回到登录页面
                res.sendRedirect(path + LOGIN_URL);
                return false;
            }
        } else {
            String USER_ID = userLoginSession.getUserId();
            logger.info("Interceptor中获取USER_ID: " + USER_ID);
        }
        logger.info("Interceptor中返回true");
        return true;
    }

@Override
public void postHandle(HttpServletRequest req, HttpServletResponse res, Object arg2, ModelAndView arg3) throws Exception {
}

@Override
public void afterCompletion(HttpServletRequest req, HttpServletResponse res, Object arg2, Exception arg3) throws Exception {
}

}
```

### 四、SSO登录接口处理逻辑
```
1.根据用户名和密码去数据库验证用户是否合法。
2.用户验证通过之后，生成SessionID,并返回给业务系统。 同时以SessionID为key,存储用户信息到redis缓存中
public JSONObject userLogin(@RequestBody JSONObject jsonObject){
UserLoginResponse userLoginResponss = new UserLoginResponse();
try {
logger.info("处理用户登录业务逻辑,接收报文"+jsonObject);
String msgWithDigesta=SecurityUtil.scfMatch(jsonObject.toString(), newXService.getPrivateKey());
//生成实体
User user = JSONObject.parseObject(msgWithDigesta,User.class);
//是否验证用户的密码
boolean isChechPassword = true;
User userInfo = anaService.loginCheckUserInfo(user,isChechPassword);
// 存储用户信息到redis缓存中
String ticket = anaService.storeUserLoginSessionInRedis(userInfo,user.getModuleCode());
userLoginResponss.setRetCode(RetCode.LOGIN_SUCCESS.getCode());
userLoginResponss.setRetMessage("用户登录成功");
userLoginResponss.setTicket(ticket);
userLoginResponss.setStatus(userInfo.getStatus());
userLoginResponss.setIsModifyPassword(userInfo.getIsModifyPassword());
} catch (Exception e) {
userLoginResponss.setRetCode(RetCode.LOGIN_FAILED.getCode());
userLoginResponss.setRetMessage(e.getMessage());
logger.info("插入用户数据到表中失败，原因："+e.getMessage());
}
logger.info("返回处理用户登录业务逻辑结果，Result{[]}"+JSONObject.toJSONString(userLoginResponss));
return JSON.parseObject(JSONObject.toJSONString(userLoginResponss));
}

/**
* 存储用户登录session信息到redis中
* @param userInfo
* @return
*/
public String storeUserLoginSessionInRedis(User userInfo,String moduleCode) {
// 存储用户ticket信息
// 使用AES加密登录用户ID生成SessionID,加密密码是配置文件里定义的64位字符串
String sessionId = AesUtil.encrypt(String.valueOf(userInfo.getUserId()), newXService.getBizkey());
String unique_ticket = userInfo.getSystemId()+sessionId+"_USER_LOGIN";
//
String ticket = userInfo.getSystemId()+sessionId+System.currentTimeMillis()+"_USER_LOGIN";

UserLoginSession userLoginSession = new UserLoginSession();
userLoginSession.setUserId(String.valueOf(userInfo.getUserId()));
userLoginSession.setUserName(userInfo.getUserName());
userLoginSession.setUserLoginName(userInfo.getUserLoginName());
// 获取权限
List<Permission> permissions = getUserPermissions(userInfo.getUserId());
userLoginSession.setPermissions(permissions);

userLoginSession.setModuleCode(StringUtils.killNull(userInfo.getModuleCode()));
userLoginSession.setLastLoginTime(userInfo.getLastLoginTime());
userLoginSession.seteId(StringUtils.killNull(userInfo.geteId()));
userLoginSession.setSessionId(ticket);
userLoginSession.setUserInfo(userInfo);

//限制唯一登录，删除上一个用户信息
if (redisService.exists(unique_ticket))
redisService.del(redisService.get(unique_ticket));

redisService.set(unique_ticket, ticket);

logger.info("访问AnaController的login方法:放进redis"+ticket);
redisService.setKeyExpire((ticket).getBytes(),1800);

logger.info("userloginsession result ="+JSONObject.toJSONString(userLoginSession));
return ticket;
}
```

### 五、业务系统将返回的SessionID，存放到Cookie中  
```
业务系统controller的代码
@RequestMapping("/login.ajax")
public
@ResponseBody
Map<String, Object> login(@RequestParam("username2") String username2,
@RequestParam("moduleCode2") String moduleCode2,
@RequestParam("password2") String password2, String requestUrl, HttpServletResponse response) {
// 其他业务逻辑省略
String sessionId = userBySso.getTicket();
Cookie cookie = new Cookie("CORE_SESSION", sessionId);
cookie.setPath("/");
response.addCookie(cookie);
// 其他业务逻辑省略
}
```

### 六、业务系统取得Sesion信息，并验证用户信息
```
业务系统的页面发起web请求时，

在自定义拦截器(继承自HandlerInterceptor)的preHandle方法里取得session信息，
并检查用户是否登录。
Session信息取得时，首先从cookie中取得SessionId，然后根据SessionId从redis取得用户信息
public UserLoginSession getUserLoginSession(HttpServletRequest req) {
logger.info("访问getUserLoginSession");

String sessionId = "";
Cookie[] cookie = req.getCookies();
if (cookie == null) {
return null;
}
for (int i = 0; i < cookie.length; i++) {
Cookie cook = cookie[i];
if (cook.getName().equals("CORE_SESSION")) {
sessionId = cook.getValue().toString();
}
}

logger.info("访问getUserLoginSession获取sessionId： " + sessionId);

if ("".equals(sessionId)) {

return null;
}

String UserLoginSessionStr = redisService.get(sessionId);

logger.info("访问getUserLoginSession获取USERLOGINSESSION： " + UserLoginSessionStr);

if (null == UserLoginSessionStr || "".equals(UserLoginSessionStr)) {

return null;
}

UserLoginSession userLoginSession = (UserLoginSession) JSONObject.toJavaObject(JSONObject.parseObject(UserLoginSessionStr), UserLoginSession.class);
logger.info("访问getUserLoginSession获取USER_ID成功： " + userLoginSession.getUserId());
redisService.setKeyExpire((sessionId).getBytes(), 1800);
redisService.setKeyExpire((userLoginSession.getTicketRole()).getBytes(),1800);
return userLoginSession;
}
```
