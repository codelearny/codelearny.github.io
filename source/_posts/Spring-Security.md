---
title: Spring Security 学习笔记
date: 2021-04-04 11:30:45
tags: [Spring,Security]
categories:
    - [Java,Spring,Spring Security]
---
# Spring Security 概览

## 安全框架主要做了两件事：
authentication (你是谁?)  
authorization (你能做什么?)

### Web
#### Servlet
`Spring Security`的`Servlet`支持基于 `Servlet Filter`

`Spring`提供了一个`Filter`接口实现`DelegatingFilterProxy`来链接`Servlet`容器和`Spring`容器，它可以通过标准`Servlet`容器机制注册，并将实际处理委托给`Spring`容器中的`Bean`
```java
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		// Lazily initialize the delegate if necessary.
		// 懒加载机制延迟初始化 delegate实例变量使用volatile修饰
		Filter delegateToUse = this.delegate;
		if (delegateToUse == null) {
			synchronized (this.delegateMonitor) {
				delegateToUse = this.;
				if (delegateToUse == null) {
					// 查找`WebApplicationContext`容器
					WebApplicationContext wac = findWebApplicationContext();
					if (wac == null) {
						throw new IllegalStateException("No WebApplicationContext found: " +
								"no ContextLoaderListener or DispatcherServlet registered?");
					}
					// 初始化委托类（从容器中取出Bean）
					delegateToUse = initDelegate(wac);
				}
				this.delegate = delegateToUse;
			}
		}
		// 实际处理委托给 delegate
		// Let the delegate perform the actual doFilter operation.
		invokeDelegate(delegateToUse, request, response, filterChain);
	}
	
	protected void invokeDelegate(
			Filter delegate, ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		delegate.doFilter(request, response, filterChain);
	}
```
#### FilterChainProxy
`Spring Security`中实际处理的工作由`FilterChainProxy`完成

`FilterChainProxy`是一个特殊的`Filter`，它将处理逻辑再次委托给`SecurityFilterChain`，并通过`DelegatingFilterProxy`注册到`Servlet`容器
```java
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//确保清理逻辑不重复
		boolean clearContext = request.getAttribute(FILTER_APPLIED) == null;
		if (!clearContext) {
			doFilterInternal(request, response, chain);
			return;
		}
		try {
			request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
			doFilterInternal(request, response, chain);
		}
		catch (RequestRejectedException ex) {
			this.requestRejectedHandler.handle((HttpServletRequest) request, (HttpServletResponse) response, ex);
		}
		finally {
			//清除上下文
			SecurityContextHolder.clearContext();
			request.removeAttribute(FILTER_APPLIED);
		}
	}
	//内部处理逻辑
	private void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		FirewalledRequest firewallRequest = this.firewall.getFirewalledRequest((HttpServletRequest) request);
		HttpServletResponse firewallResponse = this.firewall.getFirewalledResponse((HttpServletResponse) response);
		List<Filter> filters = getFilters(firewallRequest);
		if (filters == null || filters.size() == 0) {
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.of(() -> "No security for " + requestLine(firewallRequest)));
			}
			firewallRequest.reset();
			chain.doFilter(firewallRequest, firewallResponse);
			return;
		}
		if (logger.isDebugEnabled()) {
			logger.debug(LogMessage.of(() -> "Securing " + requestLine(firewallRequest)));
		}
		VirtualFilterChain virtualFilterChain = new VirtualFilterChain(firewallRequest, chain, filters);
		virtualFilterChain.doFilter(firewallRequest, firewallResponse);
	}
    //从内部的过滤器中匹配
	private List<Filter> getFilters(HttpServletRequest request) {
		int count = 0;
		for (SecurityFilterChain chain : this.filterChains) {
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Trying to match request against %s (%d/%d)", chain, ++count,
						this.filterChains.size()));
			}
			// 查找到第一个符合条件的`SecurityFilterChain`
			if (chain.matches(request)) {
				return chain.getFilters();
			}
		}
		return null;
	}
```
#### SecurityFilterChain
`SpringBoot`环境会自动注入一个默认的`SecurityFilterChain`，包含多个默认的`Filter`，通过`SecurityConfigurer`接口配置，可以通过自定义`WebSecurityConfigurerAdapter`或`SecurityFilterChain`来替换默认的`SecurityFilterChain`。


### Authentication
#### 安全架构组件
##### SecurityContextHolder
认证模型的核心，存储认证信息`SecurityContext`，拥有多种存储策略，默认使用`ThreadLocal`存储。`FilterChainProxy`确保处理完成会清理存储。 
##### SecurityContext
存储认证信息 Authentication 的实体。  
##### Authentication 
存储用于认证的信息，包括 ：`principal` （主体），`credentials`（凭证），`authorities`（权限），例如`UsernamePasswordAuthenticationToken`
##### GrantedAuthority
授予主体的权限，`Authentication.getAuthorities()`方法提供`GrantedAuthority`权限的集合，通常可以用来表示角色。
例如基于用户名、密码的认证，使用`UserDetailsService`加载权限集合
##### AuthenticationManager
框架用于认证的策略接口，只有一个方法，对入参 Authentication 进行认证，认证失败抛出异常，无法认证返回null
##### ProviderManager
`AuthenticationManager`的扩展，增加了一个`supports`方法，允许调用者询问是否支持给定`Authentication`类型的认证。`ProviderManager`持有`AuthenticationProvider`的集合组成的认证链路用以支持多种认证机制，其中一个认证通过，认证便成功。
通常在应用中受保护的资源会分为多个类别或分组，每个组应用一个`ProviderManager`，并且共享一个`parent`，`parent`用于处理公共的认证逻辑，作为所有`providers`的备用方案
##### AuthenticationProvider
用于执行具体`Authentication`类型的认证，例如`DaoAuthenticationProvider`支持基于用户名、密码的认证
##### Request Credentials with AuthenticationEntryPoint
`AuthenticationEntryPoint`用于响应客户端请求凭证，例如重定向至登录页，返回`WWW-Authenticate`响应头
##### AbstractAuthenticationProcessingFilter
认证处理的拦截器，从`HttpServletRequest`中取得用于认证的信息，封装为`Authentication`（例如：`UsernamePasswordAuthenticationToken`）。然后调用`AuthenticationManager`进行认证。

认证成功，调用`SessionAuthenticationStrategy`处理登录成功的`Session`信息，保存认证信息到`SecurityContextHolder`，随后`SecurityContextPersistenceFilter`保存`SecurityContext`至`HttpSession`。调用`RememberMeServices.loginSuccess`，发布`InteractiveAuthenticationSuccessEvent`事件，调用`AuthenticationSuccessHandler`。

认证失败，清理`SecurityContextHolder`，调用`RememberMeServices.loginFail`，调用`AuthenticationFailureHandler`。
##### Session Management
`HTTP session`的管理主要由`SessionManagementFilter`和`SessionAuthenticationStrategy`两个接口联合完成，通常包括防御会话固定攻击，指定会话超时时间，限制单个用户并发会话数等。
##### Anonymous Authentication
匿名认证，`Spring Security`提供了一种便捷的方式，对于未认证用户的行为进行统一管理

#### 认证机制
##### 基于用户名、密码的认证
`Spring Security`提供了如下内建的机制来获取用户名、密码
+ Form Login
+ Basic Authentication
+ Digest Authentication

另外有如下的存储机制，可以和以上的获取机制任意组合
+ 简单的基于内存存储 In-Memory Authentication
+ 基于数据库的 JDBC Authentication
+ 自定义存储 UserDetailsService
+  LDAP Authentication
###### 表单登录
1. 未认证的用户登录访问敏感资源`/private`
2. `FilterSecurityInterceptor`拦截请求，抛出`AccessDeniedException`
3. `ExceptionTranslationFilter`拦截异常，重定向请求
4. 浏览器请求登录页
5. 登录页提交用户名密码
6. `UsernamePasswordAuthenticationFilter`拦截请求，从`HttpServletRequest`提取信息创建`UsernamePasswordAuthenticationToken`
7. `AuthenticationManager`认证信息

显示配置表单登录如下
```java
protected void configure(HttpSecurity http) {
    http
        // ...
        .formLogin(withDefaults());
}
```
可以自定义配置
```java
protected void configure(HttpSecurity http) throws Exception {
    http
        // ...
        .formLogin(form -> form
            .loginPage("/login")
            .permitAll()
        );
}
```
###### Basic HTTP 认证
流程和表单登录类似，`ExceptionTranslationFilter`返回`WWW-Authenticate`响应头，`BasicAuthenticationFilter`拦截请求，从请求头`Authorization`中提取信息创建`UsernamePasswordAuthenticationToken`

显示配置
```java
protected void configure(HttpSecurity http) {
    http
        // ...
        .httpBasic(withDefaults());
}
```
###### JDBC 认证
`JdbcDaoImpl`实现了`UserDetailsService`接口，使用`JDBC`认证用户名、密码。`JdbcUserDetailsManager`扩展了`JdbcDaoImpl`并实现了`UserDetailsManager`，来管理`UserDetails`
###### UserDetails
认证主体，`UserDetailsService`生成`UserDetails`，`DaoAuthenticationProvider`验证`UserDetails`并返回`Authentication`
###### UserDetailsService
加载用户数据的核心接口，由`DaoAuthenticationProvider`用来检索用户名、密码和其他属性以便认证，可以自定义检索逻辑，例如从数据库查询
###### PasswordEncoder
`Spring Security`提供了`PasswordEncoder`接口存储密码，内置多种算法实现，如`bcrypt`，`pbkdf2`等
###### DaoAuthenticationProvider
`AuthenticationProvider`接口的实现，使用`UserDetailsService`和`PasswordEncoder`认证用户名和密码。
认证流程大致描述如下：
1. 从获取用户名密码的拦截器（例如表单登录使用`UsernamePasswordAuthenticationFilter`）中解析请求信息，将认证所需信息封装到`UsernamePasswordAuthenticationToken`，交给`AuthenticationManager`进行认证
2. `AuthenticationManager`的实现是`ProviderManager`,`ProviderManager`委托给`DaoAuthenticationProvider`执行
3. `DaoAuthenticationProvider`通过`UserDetailsService`检索相关信息，得到`UserDetails`
4. `DaoAuthenticationProvider`使用`PasswordEncoder`验证`UserDetails`
5. 验证通过的`UserDetails`会被封装到`UsernamePasswordAuthenticationToken`，返回认证信息，进行过滤链后续处理
### Authorization
鉴权是指验证用户访问系统资源的权力，它的前提是用户身份已经通过认证。
#### 框架结构
##### 权限
在`Authentication`中包含`GrantedAuthority`构成的集合，这些代表授予主体的权限。在`AuthenticationManager`认证过程中，保存到`Authentication`，在后续的鉴权过程中由`AccessDecisionManager`使用。
权限通常可以简单的使用字符串标识，比如角色名称，可以使用方法`getAuthority()`返回值精确标识。如果是更复杂的情况，可以自定义`AccessDecisionManager`支持`GrantedAuthority`的具体实现，并且方法`getAuthority()`必须返回`null`。
##### 前置处理
`Spring Security`提供了拦截机制来控制方法调用或者web请求的访问。`AccessDecisionManager`在`AbstractSecurityInterceptor`中访问安全对象之前被调用，来决定是否有权限访问某种资源。
###### 基于投票的AccessDecisionManager实现
`Spring Security`提供了一种投票机制，一组`AccessDecisionVoter`轮询决定授予，拒绝或者弃权。默认提供了三种投票机制的实现
* ConsensusBased 票多胜出，参数可以控制全部弃权或票数相等的情况
* AffirmativeBased 一票通过，参数可以控制全部弃权的情况
* UnanimousBased 一票否决，参数可以控制全部弃权的情况
`RoleVoter`是比较常用的`AccessDecisionVoter`实现，使用角色名称标识并带有`ROLE_`前缀，角色不匹配拒绝访问，没有`ROLE_`前缀则弃权。
##### 后置处理
有些情况下，需要对安全对象的返回值做权限控制，使用`AOP`可以实现这一点，但是`Spring Security`提供了一种便捷的钩子来处理此类问题。`AfterInvocationManager`有唯一的实现`AfterInvocationProviderManager`，轮询一组`AfterInvocationProvider`，每个`provider`都可以修改返回的对象或者抛出拒绝访问的异常。
##### 角色分级
一个常见的需求是，一个角色可能包含多个其他角色的权限，例如`系统管理员`和`普通用户`，系统管理员包含普通用户的所有权限，除了直接授权还可以使系统管理员包含普通用户的角色，也就是角色分级机制，使用`RoleHierarchyVoter`配置不同角色直接的包含关系。
#### web请求认证过程
1. `FilterSecurityInterceptor`从`SecurityContextHolder`中取出`Authentication`
2. 根据`HttpServletRequest`，`HttpServletResponse`，`FilterChain`创建`FilterInvocation`
3. `FilterInvocation`传递给`SecurityMetadataSource`获取`ConfigAttribute`
4. `Authentication`，`FilterInvocation`，`ConfigAttribute`s传递给`AccessDecisionManager`
   * 如果授权被拒绝，则抛出`AccessDeniedException`，然后由`ExceptionTranslationFilter`处理。
   * 如果允许访问，`FilterSecurityInterceptor`将后续访问`FilterChain`。
#### 基于表达式的访问控制
`Spring Security`使用`Spring EL`来支持基于表达式的访问控制。使用`SecurityExpressionRoot`作为根对象，以便提供内置表达式和对当前认证主体等值的访问。
例如`hasRole(String role)`，方法可在根对象中查看。
##### web安全表达式
`web`环境中使用`WebSecurityExpressionRoot`，可以直接在表达式中使用`request`引用`HttpServletRequest`对象，此时使用`WebExpressionVoter`执行表达式鉴权。
还可以通过`Spring Bean`方式自定义权限控制
```java
public class WebSecurity {
	public boolean checkUserId(Authentication authentication, int id) {
			...
	}
}
```
通过@引用`Spring Bean`，通过#引用路径变量
```java
http
    .authorizeRequests(authorize -> authorize
        .antMatchers("/user/{userId}/**").access("@webSecurity.checkUserId(authentication,#userId)")
        ...
    );
```
##### method安全表达式
方法级别的安全使用一系列注解实现，根对象为`MethodSecurityExpressionRoot`
* `@PreAuthorize`
方法实际执行前判断是否可以执行，同样可以引用方法入参，`DefaultSecurityParameterNameDiscoverer`用来发现入参的名称
```java
@PreAuthorize("hasPermission(#contact, 'admin')")
public void deletePermission(Contact contact, Sid recipient, Permission permission);
```
另外同样支持`Spring-EL`的各种特性
```java
@PreAuthorize("#contact.name == authentication.name")
public void doSomething(Contact contact);
```
* `@PostAuthorize`
可用于在方法执行后校验，可通过`returnObject`访问方法返回值
```java
@PostAuthorize("returnObject.id%2==0")
public User check(List<Integer> users);
```
* `@PreFilter`
可用于过滤集合类的入参，移除表达式结果为`false`的元素，多个集合可使用`filterTarget`指定，`filterObject`用来引用集合中当前元素
```java
@PreFilter(filterTarget="users", value="filterObject%2==0")
public void remain(List<Integer> users, List<String> usernames);
```
* `@PostFilter`
可用于过滤集合类的执行结果，移除表达式结果为`false`的元素，`filterObject`用来引用集合中当前元素
```java
@PreAuthorize("hasRole('USER')")
@PostFilter("hasPermission(filterObject, 'read') or hasPermission(filterObject, 'admin')")
public List<Contact> getAll();
```
为了代码可读性，可以定义元注解，对于复杂的表达式的重用特别便捷
```java
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("#contact.name == authentication.name")
public @interface ContactPermission {}
```
#### 安全对象实现
`Spring Security`中的安全对象指所有需要被安全限制的对象，如方法调用，web请求等。通过拦截器机制实现安全控制，有动态和静态两种方式
1. 动态的是通过`MethodSecurityInterceptor`实现的，基于AOP联盟，依赖`Spring`应用上下文通过代理实现织入，主要用于服务层安全
2. `AspectJSecurityInterceptor`通过`AspectJ`编译器实现静态织入，主要用于领域对象实例安全
#### 方法安全
从2.0版本以来，`Spring Security`极大的提高了对服务层方法安全的支持，它支持`JSR-250`注释和`@Secured`注释。从3.0开始，还可以使用基于表达式的注解。可以使用`intercept-methods`装饰单个`Bean`，或者可以使用`AspectJ`风格的切面保护多个`Bean`。
##### 注解支持
在`@Configuration`注解的实例上使用`@EnableGlobalMethodSecurity`开启注解支持。
注解在`Spring Bean`中使用才能生效--基于AOP，不在`Spring`上下文中的方法可使用`AspectJ`。
指定`prePostEnabled`属性为`true`可以开启`pre post`系列注解，
指定`securedEnabled`属性为`true`可以开启`Secured`注解，
指定`jsr250Enabled`属性为`true`可以开启`JSR-250`系列注解。

**注意**：可以同时开启多种注解方案在同一应用中，但是在同一个类中只有一种类型注解可以生效。

`@EnableGlobalMethodSecurity`配置类可继承`GlobalMethodSecurityConfiguration`自定义设置 。
#### 领域对象安全
##### 前言
相比于web和方法安全，实际应用中通常会定义更复杂的权限控制，而且安全决策需要同时包括`who`（身份验证）、`where`（方法调用）和`what`（领域对象）。
考虑一个常见的需求，有两种角色，卖家和客户。卖家可以访问客户的数据，客户之间也有部分信息可以互相查看，使用`Spring Security`，通常有以下几种方案。
1. 业务代码中直接控制权限访问，例如从`SecurityContextHolder`中取得认证数据，查询数据库获得领域对象信息。
2. 实现一个`AccessDecisionVoter`，访问`Authentication`中的权限数据，自定义访问其他领域对象的权限。
3. 实现一个`AccessDecisionVoter`，在投票器中查询数据库获得领域对象信息，从而做出鉴权决策。

第一种方案，业务代码强关联，单元测试困难，领域对象的鉴权不能复用。
第二种方案，如果权限数据量很大，加载权限消耗的内存和时间可能无法接受。
最后一种没有前面描述的问题，并且实现了关注点分离，但是它仍然是低效的，因为在投票器和业务方法中都检索数据库访问领域对象信息，这显然不合理。
另外，上面的方案都需要从头开始编写权限控制列表（ACL）持久化和业务代码。
`Spring Security`为我们提供了一种便捷的域对象安全管理策略。
##### 核心概念
`Spring Security`领域对象安全功能以`ACL`的概念为核心，系统中每一个领域对象实例都拥有各自的`ACL`，记录哪些人可以哪些人不可以使用该领域对象。
基于这一点，`Spring Security`为应用程序提供了三个主要的`ACL`相关功能：
1. 高效检索所有领域对象ACL条目（并且修改他们）的方法
2. 在方法调用之前，确保给定主体被允许处理对象方法
3. 在方法调用之后，确保给定主体被允许处理对象或者返回值的方法

ACL模块的主要功能之一是提供检索ACL的高性能方法，这个ACL存储库的功能十分重要，因为系统中的每个领域对象都有可能访问多个ACL条目，并且每个ACL可能从其他ACL继承，组成类似树一样的结构。
ACL功能经过仔细设计，以提供高性能检索，可拔插缓存，死锁最小化数据库更新，独立于ORM框架（直接使用JDBC），适当的封装，透明的数据库更新等特性。

### CSRF
Cross Site Request Forgery 跨站请求伪造，Spring Security默认启用csrf保护，CsrfFilter针对（"GET", "HEAD", "TRACE", "OPTIONS"）以外的方法生效，LazyCsrfTokenRepository将 CsrfToken 值存储在 HttpSession 中，并指定前端把CsrfToken 值放在名为“_csrf”的请求参数或名为“X-CSRF-TOKEN”的请求头字段里

### 异常处理
`ExceptionTranslationFilter`用于处理`AuthenticationException`（未认证）和`AccessDeniedException`（拒绝访问） ，分别由`AuthenticationEntryPoint`，`AccessDeniedHandler`接口处理，可以自定义处理逻辑
```java
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
		//添加自定义未授权和未登录结果返回
        httpSecurity.exceptionHandling().accessDeniedHandler(restAccessDeniedHandler).authenticationEntryPoint(restAuthenticationEntryPoint);
    }
}
```

## Java Configuration
### @EnableWebSecurity
`@EnableWebSecurity`注解启用`Spring Security`（`Spring Boot`自动开启）
```java
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import({ WebSecurityConfiguration.class, SpringWebMvcImportSelector.class, OAuth2ImportSelector.class,
		HttpSecurityConfiguration.class })
@EnableGlobalAuthentication
@Configuration
public @interface EnableWebSecurity {

	boolean debug() default false;

}
```
引入了`WebSecurityConfiguration`自动配置类，默认配置了一个`SecurityFilterChain`，由`webSecurity`构建
```java

	/**
	 * Creates the Spring Security Filter Chain
	 * @return the {@link Filter} that represents the security filter chain
	 * @throws Exception
	 */
	@Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public Filter springSecurityFilterChain() throws Exception {
		boolean hasConfigurers = this.webSecurityConfigurers != null && !this.webSecurityConfigurers.isEmpty();
		boolean hasFilterChain = !this.securityFilterChains.isEmpty();
		// SecurityConfigurer SecurityFilterChain 二选一
		Assert.state(!(hasConfigurers && hasFilterChain),
				"Found WebSecurityConfigurerAdapter as well as SecurityFilterChain. Please select just one.");
		if (!hasConfigurers && !hasFilterChain) {
			// 未配置的默认选项
			WebSecurityConfigurerAdapter adapter = this.objectObjectPostProcessor
					.postProcess(new WebSecurityConfigurerAdapter() {
					});
			this.webSecurity.apply(adapter);
		}
		for (SecurityFilterChain securityFilterChain : this.securityFilterChains) {
			this.webSecurity.addSecurityFilterChainBuilder(() -> securityFilterChain);
			for (Filter filter : securityFilterChain.getFilters()) {
				if (filter instanceof FilterSecurityInterceptor) {
					this.webSecurity.securityInterceptor((FilterSecurityInterceptor) filter);
					break;
				}
			}
		}
		//可以实现 WebSecurityCustomizer 接口定制构建过程
		for (WebSecurityCustomizer customizer : this.webSecurityCustomizers) {
			customizer.customize(this.webSecurity);
		}
		//执行构建
		return this.webSecurity.build();
	}

```
### WebSecurity
`webSecurity`的初始化及`WebSecurityConfigurerAdapter`的注入，初始化需要`ObjectPostProcessor`，这是一个对象处理器，通常用来处理`Aware`方法，`InitializingBean.afterPropertiesSet()`，` DisposableBean.destroy()` 方法，以便没有使用容器管理的对象支持`Spring`的一些周期函数。
```java
	@Autowired(required = false)
	public void setFilterChainProxySecurityConfigurer(ObjectPostProcessor<Object> objectPostProcessor,
			@Value("#{@autowiredWebSecurityConfigurersIgnoreParents.getWebSecurityConfigurers()}") List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers)
			throws Exception {
		//周期函数的处理
		this.webSecurity = objectPostProcessor.postProcess(new WebSecurity(objectPostProcessor));
		if (this.debugEnabled != null) {
			this.webSecurity.debug(this.debugEnabled);
		}
		//支持Order接口排序或注解排序
		webSecurityConfigurers.sort(AnnotationAwareOrderComparator.INSTANCE);
		Integer previousOrder = null;
		Object previousConfig = null;
		for (SecurityConfigurer<Filter, WebSecurity> config : webSecurityConfigurers) {
			Integer order = AnnotationAwareOrderComparator.lookupOrder(config);
			if (previousOrder != null && previousOrder.equals(order)) {
				throw new IllegalStateException("@Order on WebSecurityConfigurers must be unique. Order of " + order
						+ " was already used on " + previousConfig + ", so it cannot be used on " + config + " too.");
			}
			previousOrder = order;
			previousConfig = config;
		}
		//SecurityConfigurer 接口用于定制构建的过程，有 init，configure 两个生命周期函数，通常使用它的子类 WebSecurityConfigurerAdapter
		for (SecurityConfigurer<Filter, WebSecurity> webSecurityConfigurer : webSecurityConfigurers) {
			this.webSecurity.apply(webSecurityConfigurer);
		}
		this.webSecurityConfigurers = webSecurityConfigurers;
	}
```
`WebSecurity`继承了`AbstractConfiguredSecurityBuilder<Filter, WebSecurity>`，`AbstractSecurityBuilder`，是一个`SecurityBuilder`，用于构建`FilterChainProxy`，可以使用`SecurityConfigurer`，`WebSecurityConfigurerAdapter`或`WebSecurityCustomizer`定制构建过程。

`AbstractConfiguredSecurityBuilder`使用建造者模式，允许多个`SecurityConfigurer`策略对象配置不同的目标，分离构建过程，
使用模板方法定义构建过程，依次应用`SecurityConfigurer`的`init`，`configure`方法
```java
public abstract class AbstractConfiguredSecurityBuilder<O, B extends SecurityBuilder<O>>
		extends AbstractSecurityBuilder<O>{
	//模板方法			
	@Override
	protected final O doBuild() throws Exception {
		synchronized (this.configurers) {
			this.buildState = BuildState.INITIALIZING;
			beforeInit();
			init();
			this.buildState = BuildState.CONFIGURING;
			beforeConfigure();
			configure();
			this.buildState = BuildState.BUILDING;
			O result = performBuild();
			this.buildState = BuildState.BUILT;
			return result;
		}
	}
	//子类实现，在init方法之前执行
	protected void beforeInit() throws Exception {
	}
	//依次调用SecurityConfigurer.init
	private void init() throws Exception {
		Collection<SecurityConfigurer<O, B>> configurers = getConfigurers();
		for (SecurityConfigurer<O, B> configurer : configurers) {
			configurer.init((B) this);
		}
		for (SecurityConfigurer<O, B> configurer : this.configurersAddedInInitializing) {
			configurer.init((B) this);
		}
	}
	//子类实现，在configure方法之前执行
	protected void beforeConfigure() throws Exception {
	}
	//依次调用SecurityConfigurer.configure
	private void configure() throws Exception {
		Collection<SecurityConfigurer<O, B>> configurers = getConfigurers();
		for (SecurityConfigurer<O, B> configurer : configurers) {
			configurer.configure((B) this);
		}
	}
	//子类执行具体构建
	protected abstract O performBuild() throws Exception;
}
```
`WebSecurity`使用`SecurityBuilder<? extends SecurityFilterChain>`定制构建，通常使用`WebSecurityConfigurerAdapter`，分别执行`SecurityFilterChain`列表的构建，每个`SecurityBuilder<? extends SecurityFilterChain>`构建一个`SecurityFilterChain`实例，多个实例构建为`FilterChainProxy`实例
```java
	@Override
	protected Filter performBuild() throws Exception {
		Assert.state(!this.securityFilterChainBuilders.isEmpty(),
				() -> "At least one SecurityBuilder<? extends SecurityFilterChain> needs to be specified. "
						+ "Typically this is done by exposing a SecurityFilterChain bean "
						+ "or by adding a @Configuration that extends WebSecurityConfigurerAdapter. "
						+ "More advanced users can invoke " + WebSecurity.class.getSimpleName()
						+ ".addSecurityFilterChainBuilder directly");
		int chainSize = this.ignoredRequests.size() + this.securityFilterChainBuilders.size();
		List<SecurityFilterChain> securityFilterChains = new ArrayList<>(chainSize);
		//不需要进行安全控制的部分
		for (RequestMatcher ignoredRequest : this.ignoredRequests) {
			securityFilterChains.add(new DefaultSecurityFilterChain(ignoredRequest));
		}
		//分别执行构建
		for (SecurityBuilder<? extends SecurityFilterChain> securityFilterChainBuilder : this.securityFilterChainBuilders) {
			securityFilterChains.add(securityFilterChainBuilder.build());
		}
		FilterChainProxy filterChainProxy = new FilterChainProxy(securityFilterChains);
		//设置防火墙
		if (this.httpFirewall != null) {
			filterChainProxy.setFirewall(this.httpFirewall);
		}
		//设置请求拒绝异常处理类
		if (this.requestRejectedHandler != null) {
			filterChainProxy.setRequestRejectedHandler(this.requestRejectedHandler);
		}
		//初始化
		filterChainProxy.afterPropertiesSet();

		Filter result = filterChainProxy;
		if (this.debugEnabled) {
			this.logger.warn("\n\n" + "********************************************************************\n"
					+ "**********        Security debugging is enabled.       *************\n"
					+ "**********    This may include sensitive information.  *************\n"
					+ "**********      Do not use in a production system!     *************\n"
					+ "********************************************************************\n\n");
			result = new DebugFilter(filterChainProxy);
		}
		this.postBuildAction.run();
		return result;
	}
```
`securityFilterChainBuilders`通常由框架自动注入，`WebSecurityConfigurerAdapter.init(WebSecurity)`，在`WebSecurity.init`的时候执行
```java
	@Override
	public void init(WebSecurity web) throws Exception {
		HttpSecurity http = getHttp();
		//初始化时注入
		web.addSecurityFilterChainBuilder(http).postBuildAction(() -> {
			FilterSecurityInterceptor securityInterceptor = http.getSharedObject(FilterSecurityInterceptor.class);
			web.securityInterceptor(securityInterceptor);
		});
	}
```
### HttpSecurity
`HttpSecurity`继承了`AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain, HttpSecurity>`，`AbstractSecurityBuilder`，是一个`SecurityBuilder`，用于构建`DefaultSecurityFilterChain`，可以配置特定`HTTP`请求的web安全，多个`HttpSecurity`可以分别配置不同维度的安全设置，同样使用父类的模板方法执行构建过程。
```java
public final class HttpSecurity extends AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain, HttpSecurity>
		implements SecurityBuilder<DefaultSecurityFilterChain>, HttpSecurityBuilder<HttpSecurity> {
	//设置多个SecurityConfigurer通用的AuthenticationManager
	@Override
	protected void beforeConfigure() throws Exception {
		setSharedObject(AuthenticationManager.class, getAuthenticationRegistry().build());
	}
	//生成针对特定HTTP请求的安全过滤器链
	@Override
	protected DefaultSecurityFilterChain performBuild() {
		this.filters.sort(this.comparator);
		return new DefaultSecurityFilterChain(this.requestMatcher, this.filters);
	}
	//用于匹配特定的请求，这些请求可以应用这里配置的安全设置
	public HttpSecurity requestMatcher(RequestMatcher requestMatcher) {
		this.requestMatcher = requestMatcher;
		return this;
	}
}
```
`HttpSecurity`可以直接增加过滤器配置，另外还有很多预设的方法配置，例如：
```java
	//使用链式方法配置
	public HttpBasicConfigurer<HttpSecurity> httpBasic() throws Exception {
		return getOrApply(new HttpBasicConfigurer<>());
	}
	//避免重复配置
	private <C extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> C getOrApply(C configurer)
			throws Exception {
		C existingConfig = (C) getConfigurer(configurer.getClass());
		if (existingConfig != null) {
			return existingConfig;
		}
		return apply(configurer);
	}
	//预设部分属性，加入配置器的集合中，在构建阶段调用相应的策略方法
	public <C extends SecurityConfigurerAdapter<O, B>> C apply(C configurer) throws Exception {
		configurer.addObjectPostProcessor(this.objectPostProcessor);
		configurer.setBuilder((B) this);
		add(configurer);
		return configurer;
	}
	//使用接口配置
	public HttpSecurity httpBasic(Customizer<HttpBasicConfigurer<HttpSecurity>> httpBasicCustomizer) throws Exception {
		httpBasicCustomizer.customize(getOrApply(new HttpBasicConfigurer<>()));
		return HttpSecurity.this;
	}
	//直接配置过滤器
	@Override
	public HttpSecurity addFilter(Filter filter) {
		Class<? extends Filter> filterClass = filter.getClass();
		if (!this.comparator.isRegistered(filterClass)) {
			throw new IllegalArgumentException("The Filter class " + filterClass.getName()
					+ " does not have a registered order and cannot be added without a specified order. Consider using addFilterBefore or addFilterAfter instead.");
		}
		this.filters.add(filter);
		return this;
	}
```
以`HttpBasicConfigurer`为例
```java
public final class HttpBasicConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<HttpBasicConfigurer<B>, B> {
	//模板方法 init 阶段执行策略函数，可对 HttpSecurity 进行配置
	@Override
	public void init(B http) {
		registerDefaults(http);
	}
	//模板方法 configure 阶段执行，对 HttpSecurity 加入配置完成的 filter
	@Override
	public void configure(B http) {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		BasicAuthenticationFilter basicAuthenticationFilter = new BasicAuthenticationFilter(authenticationManager,
				this.authenticationEntryPoint);
		if (this.authenticationDetailsSource != null) {
			basicAuthenticationFilter.setAuthenticationDetailsSource(this.authenticationDetailsSource);
		}
		RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
		if (rememberMeServices != null) {
			basicAuthenticationFilter.setRememberMeServices(rememberMeServices);
		}
		basicAuthenticationFilter = postProcess(basicAuthenticationFilter);
		http.addFilter(basicAuthenticationFilter);
	}
	//继承 SecurityConfigurerAdapter ，返回构建器，用以支持链式方法调用
	public B and() {
		return getBuilder();
	}

}
```
另外还有`openidLogin`，`headers`，`cors`，`sessionManagement`，`csrf`等便捷方法
### WebSecurityConfigurerAdapter
通过`WebSecurityConfigurerAdapter`可以方便的配置`HttpSecurity`，`AuthenticationManagerBuilder`的构建过程
```java
	//配置HttpSecurity的构建
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests(authorize -> authorize
				.anyRequest().authenticated()
			)
			.formLogin(withDefaults())
			.httpBasic(withDefaults());
	}
	//配置AuthenticationManager的构建
	@Override
	protected void configure(AuthenticationManagerBuilder auth) {
	// enable in memory based authentication with a user named
	// "user" and "admin"
		auth
		.inMemoryAuthentication().withUser("user").password("password").roles("USER").and()
			.withUser("admin").password("password").roles("USER", "ADMIN");
	}
	
	// Expose the UserDetailsService as a Bean
	@Bean
	@Override
	public UserDetailsService userDetailsServiceBean() throws Exception {
	return super.userDetailsServiceBean();
	}
```
初始化`HttpSecurity`，构造需要三个参数

`ObjectPostProcessor`，用于支持`Spring`的一些周期函数

`AuthenticationManagerBuilder`，用于构建`AuthenticationManager`，认证工作都由它来完成

`sharedObjects`，在此构建器的多个`Configurer`中共享的对象

实例化之后，初始化默认配置，应用子类配置
```java
	protected final HttpSecurity getHttp() throws Exception {
		if (this.http != null) {
			return this.http;
		}
		//认证事件发布器
		AuthenticationEventPublisher eventPublisher = getAuthenticationEventPublisher();
		//localConfigureAuthenticationBldr是本地的AuthenticationManager构建器
		this.localConfigureAuthenticationBldr.authenticationEventPublisher(eventPublisher);
		//为每个filter的构建器共享的认证方案，可以根据子类自定义配置构建，子类没有重写使用默认配置
		AuthenticationManager authenticationManager = authenticationManager();
		//认证管理器构建器，每个filter拥有一个局部的认证管理器
		this.authenticationBuilder.parentAuthenticationManager(authenticationManager);
		//为每个filter的构建器共享的对象
		Map<Class<?>, Object> sharedObjects = createSharedObjects();
		this.http = new HttpSecurity(this.objectPostProcessor, this.authenticationBuilder, sharedObjects);
		//可以通过设置disableDefaults关闭默认配置
		if (!this.disableDefaults) {
			applyDefaultConfiguration(this.http);
			ClassLoader classLoader = this.context.getClassLoader();
			//spring的SPI机制加载默认配置
			List<AbstractHttpConfigurer> defaultHttpConfigurers = SpringFactoriesLoader
					.loadFactories(AbstractHttpConfigurer.class, classLoader);
			for (AbstractHttpConfigurer configurer : defaultHttpConfigurers) {
				this.http.apply(configurer);
			}
		}
		//回调函数修改默认配置
		configure(this.http);
		return this.http;
	}
	//应用默认的配置
	private void applyDefaultConfiguration(HttpSecurity http) throws Exception {
		http.csrf();
		http.addFilter(new WebAsyncManagerIntegrationFilter());
		http.exceptionHandling();
		http.headers();
		http.sessionManagement();
		http.securityContext();
		http.requestCache();
		http.anonymous();
		http.servletApi();
		http.apply(new DefaultLoginPageConfigurer<>());
		http.logout();
	}
	//共享对象
	private Map<Class<?>, Object> createSharedObjects() {
		Map<Class<?>, Object> sharedObjects = new HashMap<>();
		sharedObjects.putAll(this.localConfigureAuthenticationBldr.getSharedObjects());
		sharedObjects.put(UserDetailsService.class, userDetailsService());
		sharedObjects.put(ApplicationContext.class, this.context);
		sharedObjects.put(ContentNegotiationStrategy.class, this.contentNegotiationStrategy);
		sharedObjects.put(AuthenticationTrustResolver.class, this.trustResolver);
		return sharedObjects;
	}
	protected AuthenticationManager authenticationManager() throws Exception {
		//只需要初始化一次
		if (!this.authenticationManagerInitialized) {
			//设置disableLocalConfigureAuthenticationBldr为true，可在子类重写
			configure(this.localConfigureAuthenticationBldr);
			if (this.disableLocalConfigureAuthenticationBldr) {
				//配置类中获取全局默认配置authenticationManager
				this.authenticationManager = this.authenticationConfiguration.getAuthenticationManager();
			}
			else {
				//使用本地的构建器构建
				this.authenticationManager = this.localConfigureAuthenticationBldr.build();
			}
			this.authenticationManagerInitialized = true;
		}
		return this.authenticationManager;
	}
	//AuthenticationManager的构建器使用DefaultPasswordEncoderAuthenticationManagerBuilder
	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		this.context = context;
		ObjectPostProcessor<Object> objectPostProcessor = context.getBean(ObjectPostProcessor.class);
		LazyPasswordEncoder passwordEncoder = new LazyPasswordEncoder(context);
		this.authenticationBuilder = new DefaultPasswordEncoderAuthenticationManagerBuilder(objectPostProcessor,
				passwordEncoder);
		this.localConfigureAuthenticationBldr = new DefaultPasswordEncoderAuthenticationManagerBuilder(
				objectPostProcessor, passwordEncoder) {

			@Override
			public AuthenticationManagerBuilder eraseCredentials(boolean eraseCredentials) {
				WebSecurityConfigurerAdapter.this.authenticationBuilder.eraseCredentials(eraseCredentials);
				return super.eraseCredentials(eraseCredentials);
			}

			@Override
			public AuthenticationManagerBuilder authenticationEventPublisher(
					AuthenticationEventPublisher eventPublisher) {
				WebSecurityConfigurerAdapter.this.authenticationBuilder.authenticationEventPublisher(eventPublisher);
				return super.authenticationEventPublisher(eventPublisher);
			}

		};
	}
```
`HttpSecurity`可以使用`formLogin`，`httpBasic`等方法配置认证方式

通过`AuthenticationManagerBuilder`配置`AuthenticationProvider`支持具体的认证逻辑
```java
	public HttpSecurity(ObjectPostProcessor<Object> objectPostProcessor,
			AuthenticationManagerBuilder authenticationBuilder, Map<Class<?>, Object> sharedObjects) {
		super(objectPostProcessor);
		Assert.notNull(authenticationBuilder, "authenticationBuilder cannot be null");
		//authenticationBuilder加入到共享对象，通过getAuthenticationRegistry方法取出
		setSharedObject(AuthenticationManagerBuilder.class, authenticationBuilder);
		for (Map.Entry<Class<?>, Object> entry : sharedObjects.entrySet()) {
			setSharedObject((Class<Object>) entry.getKey(), entry.getValue());
		}
		ApplicationContext context = (ApplicationContext) sharedObjects.get(ApplicationContext.class);
		this.requestMatcherConfigurer = new RequestMatcherConfigurer(context);
	}
	//表单认证
	public FormLoginConfigurer<HttpSecurity> formLogin() throws Exception {
		return getOrApply(new FormLoginConfigurer<>());
	}
	//http basic头认证
	public HttpBasicConfigurer<HttpSecurity> httpBasic() throws Exception {
		return getOrApply(new HttpBasicConfigurer<>());
	}
	//取出认证管理器构建器
	private AuthenticationManagerBuilder getAuthenticationRegistry() {
		return getSharedObject(AuthenticationManagerBuilder.class);
	}
	//配置管理器构建器增加provider
	@Override
	public HttpSecurity authenticationProvider(AuthenticationProvider authenticationProvider) {
		getAuthenticationRegistry().authenticationProvider(authenticationProvider);
		return this;
	}
	//配置管理器构建器增加provider
	@Override
	public HttpSecurity userDetailsService(UserDetailsService userDetailsService) throws Exception {
		getAuthenticationRegistry().userDetailsService(userDetailsService);
		return this;
	}
	//在周期函数中完成认证管理器的构建
	@Override
	protected void beforeConfigure() throws Exception {
		setSharedObject(AuthenticationManager.class, getAuthenticationRegistry().build());
	}
```
`HttpSecurity`通过`authorizeRequests`方法控制需要保护的资源，通过url匹配的方式
```java
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			//url /admin/** 需要角色ADMIN
			.antMatchers("/admin/**").hasRole("ADMIN")
			.antMatchers("/**").hasRole("USER")
			.and().formLogin();
	}
```
### ExpressionUrlAuthorizationConfigurer
`authorizeRequests`通过`ExpressionUrlAuthorizationConfigurer`类配置
```java
	public ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests()
			throws Exception {
		ApplicationContext context = getContext();
		return getOrApply(new ExpressionUrlAuthorizationConfigurer<>(context)).getRegistry();
	}
```
`ExpressionUrlAuthorizationConfigurer`用于构建`FilterSecurityInterceptor`，以过滤器的形式控制资源访问
```java
public final class ExpressionUrlAuthorizationConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractInterceptUrlConfigurer<ExpressionUrlAuthorizationConfigurer<H>, H> {
	//初始化一个url与访问权限的注册器
	public ExpressionUrlAuthorizationConfigurer(ApplicationContext context) {
		this.REGISTRY = new ExpressionInterceptUrlRegistry(context);
	}
	//注册 url 与 访问权限 的映射关系
	private void interceptUrl(Iterable<? extends RequestMatcher> requestMatchers,
			Collection<ConfigAttribute> configAttributes) {
		for (RequestMatcher requestMatcher : requestMatchers) {
			this.REGISTRY.addMapping(
					new AbstractConfigAttributeRequestMatcherRegistry.UrlMapping(requestMatcher, configAttributes));
		}
	}

	//继承自AbstractInterceptUrlConfigurer
	@Override
	public void configure(H http) throws Exception {
		//封装url与访问权限等元数据
		FilterInvocationSecurityMetadataSource metadataSource = createMetadataSource(http);
		if (metadataSource == null) {
			return;
		}
		//创建FilterSecurityInterceptor
		FilterSecurityInterceptor securityInterceptor = createFilterSecurityInterceptor(http, metadataSource,
				http.getSharedObject(AuthenticationManager.class));
		if (this.filterSecurityInterceptorOncePerRequest != null) {
			securityInterceptor.setObserveOncePerRequest(this.filterSecurityInterceptorOncePerRequest);
		}
		securityInterceptor = postProcess(securityInterceptor);
		//作为过滤器添加到HttpSecurity
		http.addFilter(securityInterceptor);
		//作为共享对象
		http.setSharedObject(FilterSecurityInterceptor.class, securityInterceptor);
	}
	//创建FilterSecurityInterceptor实例并赋值，初始化
	private FilterSecurityInterceptor createFilterSecurityInterceptor(H http,
			FilterInvocationSecurityMetadataSource metadataSource, AuthenticationManager authenticationManager)
			throws Exception {
		FilterSecurityInterceptor securityInterceptor = new FilterSecurityInterceptor();
		securityInterceptor.setSecurityMetadataSource(metadataSource);
		//授权管理
		securityInterceptor.setAccessDecisionManager(getAccessDecisionManager(http));
		//认证管理
		securityInterceptor.setAuthenticationManager(authenticationManager);
		securityInterceptor.afterPropertiesSet();
		return securityInterceptor;
	}
}
```
### FilterSecurityInterceptor
`FilterSecurityInterceptor`通过过滤器的形式执行HTTP资源的安全处理，未经过认证的请求在这里拦截，配置拦截的url需要经过授权验证，符合权限的可以访问资源
```java
	//过滤器方法
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		invoke(new FilterInvocation(request, response, chain));
	}
	//父类方法执行安全处理
	public void invoke(FilterInvocation filterInvocation) throws IOException, ServletException {
		if (isApplied(filterInvocation) && this.observeOncePerRequest) {
			// 已经处理过， 并且每个请求只验证一次 可以跳过验证
			filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
			return;
		}
		// 标记为已处理
		if (filterInvocation.getRequest() != null && this.observeOncePerRequest) {
			filterInvocation.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
		}
		//前置处理
		InterceptorStatusToken token = super.beforeInvocation(filterInvocation);
		try {
			filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
		}
		finally {
			super.finallyInvocation(token);
		}
		//后置处理
		super.afterInvocation(token, null);
	}
```
抽象安全拦截器，抽象了安全拦截管理的通用逻辑
```java
public abstract class AbstractSecurityInterceptor
		implements InitializingBean, ApplicationEventPublisherAware, MessageSourceAware {

	protected InterceptorStatusToken beforeInvocation(Object object) {
		Assert.notNull(object, "Object was null");
		if (!getSecureObjectClass().isAssignableFrom(object.getClass())) {
			throw new IllegalArgumentException("Security invocation attempted for object " + object.getClass().getName()
					+ " but AbstractSecurityInterceptor only configured to support secure objects of type: "
					+ getSecureObjectClass());
		}
		//元数据中根据url匹配访问权限
		Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource().getAttributes(object);
		//没有配置拦截的url直接放行
		if (CollectionUtils.isEmpty(attributes)) {
			Assert.isTrue(!this.rejectPublicInvocations,
					() -> "Secure object invocation " + object
							+ " was denied as public invocations are not allowed via this interceptor. "
							+ "This indicates a configuration error because the "
							+ "rejectPublicInvocations property is set to 'true'");
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Authorized public object %s", object));
			}
			//发布事件
			publishEvent(new PublicInvocationEvent(object));
			return null; // no further work post-invocation
		}
		//未找到认证实体，发布事件 AuthenticationCredentialsNotFoundEvent，抛出异常 AuthenticationCredentialsNotFoundException
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			credentialsNotFound(this.messages.getMessage("AbstractSecurityInterceptor.authenticationNotFound",
					"An Authentication object was not found in the SecurityContext"), object, attributes);
		}
		//需要认证的调用authenticationManager进行认证
		Authentication authenticated = authenticateIfRequired();
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Authorizing %s with attributes %s", object, attributes));
		}
		// 尝试accessDecisionManager授权，没有通过权限认证会发布AuthorizationFailureEvent事件，抛出AccessDeniedException异常
		attemptAuthorization(object, attributes, authenticated);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Authorized %s with attributes %s", object, attributes));
		}
		if (this.publishAuthorizationSuccess) {
			//发布授权成功事件
			publishEvent(new AuthorizedEvent(object, attributes, authenticated));
		}

		//提供了一种机制，临时替换当前的认证信息，请求完成后重置，默认不做处理
		Authentication runAs = this.runAsManager.buildRunAs(authenticated, object, attributes);
		if (runAs != null) {
			SecurityContext origCtx = SecurityContextHolder.getContext();
			SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
			SecurityContextHolder.getContext().setAuthentication(runAs);

			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Switched to RunAs authentication %s", runAs));
			}
			// finallyInvocation中处理
			return new InterceptorStatusToken(origCtx, true, attributes, object);
		}
		this.logger.trace("Did not switch RunAs authentication since RunAsManager returned null");
		// no further work post-invocation
		return new InterceptorStatusToken(SecurityContextHolder.getContext(), false, attributes, object);

	}
	private Authentication authenticateIfRequired() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		//已经认证的 并且 总是重新验证 为 false 直接返回结果 
		if (authentication.isAuthenticated() && !this.alwaysReauthenticate) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Did not re-authenticate %s before authorizing", authentication));
			}
			return authentication;
		}
		//进行身份认证
		authentication = this.authenticationManager.authenticate(authentication);
		// Don't authenticated.setAuthentication(true) because each provider does that
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Re-authenticated %s before authorizing", authentication));
		}
		//保存重新的认证结果
		SecurityContextHolder.getContext().setAuthentication(authentication);
		return authentication;
	}
	//临时存储的认证信息，在这里重置
	protected void finallyInvocation(InterceptorStatusToken token) {
		if (token != null && token.isContextHolderRefreshRequired()) {
			SecurityContextHolder.setContext(token.getSecurityContext());
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.of(
						() -> "Reverted to original authentication " + token.getSecurityContext().getAuthentication()));
			}
		}
	}
	//后置处理 afterInvocationManager 可以在请求完成后 做一些事情
	protected Object afterInvocation(InterceptorStatusToken token, Object returnedObject) {
		if (token == null) {
			// public object
			return returnedObject;
		}
		finallyInvocation(token); // continue to clean in this method for passivity
		if (this.afterInvocationManager != null) {
			// 执行后置处理，如果有的话
			try {
				returnedObject = this.afterInvocationManager.decide(token.getSecurityContext().getAuthentication(),
						token.getSecureObject(), token.getAttributes(), returnedObject);
			}
			catch (AccessDeniedException ex) {
				publishEvent(new AuthorizationFailureEvent(token.getSecureObject(), token.getAttributes(),
						token.getSecurityContext().getAuthentication(), ex));
				throw ex;
			}
		}
		return returnedObject;
	}

}
```
### FormLoginConfigurer
表单认证通过`FormLoginConfigurer`类配置
```java
	public FormLoginConfigurer<HttpSecurity> formLogin() throws Exception {
		return getOrApply(new FormLoginConfigurer<>());
	}
```
`FormLoginConfigurer`用于构建`UsernamePasswordAuthenticationFilter`
```java
public final class FormLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractAuthenticationFilterConfigurer<H, FormLoginConfigurer<H>, UsernamePasswordAuthenticationFilter> {
	public FormLoginConfigurer() {
		super(new UsernamePasswordAuthenticationFilter(), null);
		usernameParameter("username");
		passwordParameter("password");
	}
```
### UsernamePasswordAuthenticationFilter
继承`AbstractAuthenticationProcessingFilter`，负责从请求中解析认证信息并交给`AuthenticationManager`认证
```java
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		if (this.postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}
		//从请求参数中获取用户名
		String username = obtainUsername(request);
		username = (username != null) ? username : "";
		username = username.trim();
		//从请求参数中获取密码
		String password = obtainPassword(request);
		password = (password != null) ? password : "";
		//封装token
		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
		// Allow subclasses to set the "details" property
		//token中保存额外的信息，如remoteAddress，sessionId
		setDetails(request, authRequest);
		//调用AuthenticationManager进行认证
		return this.getAuthenticationManager().authenticate(authRequest);
	}
```
### AbstractAuthenticationProcessingFilter
处理基于http请求的认证过滤器抽象类，使用模板方法，完成过滤器的工作，将认证工作委托给子类处理
```java
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//类似于适配器的处理
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}
	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//未匹配的请求不做处理
		if (!requiresAuthentication(request, response)) {
			chain.doFilter(request, response);
			return;
		}
		try {
			//模板方法，子类认证
			Authentication authenticationResult = attemptAuthentication(request, response);
			if (authenticationResult == null) {
				//认证信息为空代表无法处理
				// return immediately as subclass has indicated that it hasn't completed
				return;
			}
			//session处理的策略接口
			this.sessionStrategy.onAuthentication(authenticationResult, request, response);
			// Authentication success
			//可配置过滤器链后处理
			if (this.continueChainBeforeSuccessfulAuthentication) {
				chain.doFilter(request, response);
			}
			successfulAuthentication(request, response, chain, authenticationResult);
		}
		catch (InternalAuthenticationServiceException failed) {
			this.logger.error("An internal error occurred while trying to authenticate the user.", failed);
			unsuccessfulAuthentication(request, response, failed);
		}
		catch (AuthenticationException ex) {
			// Authentication failed
			unsuccessfulAuthentication(request, response, ex);
		}
	}
	//成功处理方法
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		//保存认证信息到SecurityContextHolder
		SecurityContextHolder.getContext().setAuthentication(authResult);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
		}
		//记住我
		this.rememberMeServices.loginSuccess(request, response, authResult);
		//发布对应事件
		if (this.eventPublisher != null) {
			this.eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
		}
		//成功回调，比如跳转到之前访问的url，可自定义
		this.successHandler.onAuthenticationSuccess(request, response, authResult);
	}
	//失败处理方法
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		//清除认证信息
		SecurityContextHolder.clearContext();
		this.logger.trace("Failed to process authentication request", failed);
		this.logger.trace("Cleared SecurityContextHolder");
		this.logger.trace("Handling authentication failure");
		//清除记住我
		this.rememberMeServices.loginFail(request, response);
		//失败回调，比如跳转到指定url，返回401等，可自定义
		this.failureHandler.onAuthenticationFailure(request, response, failed);
	}
```

