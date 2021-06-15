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

认证成功，调用`SessionAuthenticationStrategy`保存`Authentication`至`SecurityContextHolder`，`SecurityContextPersistenceFilter`保存`SecurityContext`至`HttpSession`。调用`RememberMeServices.loginSuccess`，发布`InteractiveAuthenticationSuccessEvent`事件，调用`AuthenticationSuccessHandler`。

认证失败，清理`SecurityContextHolder`，调用`RememberMeServices.loginFail`，调用`AuthenticationFailureHandler`。

#### 认证机制
##### 基于用户名、密码的认证
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
###### 密码存储
`Spring Security`提供了`PasswordEncoder`接口存储密码，内置多种算法实现，如`bcrypt`，`pbkdf2`等
###### DaoAuthenticationProvider

### CSRF
Cross Site Request Forgery 跨站请求伪造，Spring Security默认启用csrf保护，CsrfFilter针对（"GET", "HEAD", "TRACE", "OPTIONS"）以外的方法生效，LazyCsrfTokenRepository将 CsrfToken 值存储在 HttpSession 中，并指定前端把CsrfToken 值放在名为“_csrf”的请求参数或名为“X-CSRF-TOKEN”的请求头字段里

### 异常处理
ExceptionTranslationFilter 用于处理 AuthenticationException （未认证） 和 AccessDeniedException （拒绝访问） ，分别由 AuthenticationEntryPoint AccessDeniedHandler 接口处理，可以自定义处理逻辑

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