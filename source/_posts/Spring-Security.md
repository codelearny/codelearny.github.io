---
title: Spring Security
date: 2021-04-04 11:30:45
tags: [Spring,Cache]
categories:
    - [Java,Spring,Spring Security]
---
Spring Security 原理
===
* 安全框架主要做了两件事：
authentication (你是谁?)
authorization (你能做什么?)

* Web
  >Spring Security在web体系中作为一个标准 servlet filter 接入，使用FilterChainProxy代理框架中的多个SecurityFilterChain，通过DelegatingFilterProxyRegistrationBean注册一个DelegatingFilterProxy到servlet容器中。
  springboot环境会自动注入一个默认的SecurityFilterChain，包含多个默认的filter，通过SecurityConfigurer接口配置，可以通过自定义WebSecurityConfigurerAdapter 或 SecurityFilterChain 来替换默认的SecurityFilterChain

* Authentication
  + SecurityContextHolder 
  >认证模型的核心，存储 SecurityContext ，拥有多种存储策略，默认使用ThreadLocal存储。FilterChainProxy 确保处理完成会清理存储。  
  + SecurityContext 
  >存储认证信息 Authentication 的实体。  
  + Authentication 
  >存储用于认证的信息，包括 ：principal （主体），credentials （凭证），authorities （权限）  
  Authentication.getAuthorities() 方法提供 GrantedAuthority 权限的集合， 通常可以用来表示角色
  + AbstractAuthenticationProcessingFilter
  >认证处理的拦截器，从 HttpServletRequest 中取得用于认证的信息，封装为Authentication（例如：UsernamePasswordAuthenticationToken）。然后调用  AuthenticationManager 进行认证。  
  认证成功，调用 SessionAuthenticationStrategy ，保存 Authentication 至 SecurityContextHolder ，SecurityContextPersistenceFilter 保存 SecurityContext 至 HttpSession。调用 RememberMeServices.loginSuccess ，发布 InteractiveAuthenticationSuccessEvent 事件，调用 AuthenticationSuccessHandler 。  
  认证失败，清理 SecurityContextHolder ，调用 RememberMeServices.loginFail ，调用 AuthenticationFailureHandler 。
  + AuthenticationManager
  >是框架用于认证的策略接口，只有一个方法，对入参 Authentication 进行认证，认证失败抛出异常，无法认证返回null
  + ProviderManager
  >是AuthenticationManager的扩展，增加了一个supports方法，允许调用者询问是否支持给定Authentication类型的认证。ProviderManager持有AuthenticationProvider的集合组成的认证链路用以支持多种认证机制，其中一个认证通过，认证便成功。通常在应用中受保护的资源会分为多个类别或分组，每个组应用一个ProviderManager，并且共享一个parent，parent用于处理公共的认证逻辑，作为所有providers的备用方案
  + AccessDecisionManager
  >类似于ProviderManager，它持有AccessDecisionVoter的集合

* 密码存储
  >Spring Security提供了 PasswordEncoder 接口存储密码，内置多种算法实现，如 bcrypt，pbkdf2等

* CSRF
  >Cross Site Request Forgery 跨站请求伪造，Spring Security默认启用csrf保护，CsrfFilter针对（"GET", "HEAD", "TRACE", "OPTIONS"）以外的方法生效，LazyCsrfTokenRepository将 CsrfToken 值存储在 HttpSession 中，并指定前端把CsrfToken 值放在名为“_csrf”的请求参数或名为“X-CSRF-TOKEN”的请求头字段里

* 异常处理
  >ExceptionTranslationFilter 用于处理 AuthenticationException （未认证） 和 AccessDeniedException （拒绝访问） ，分别由 AuthenticationEntryPoint AccessDeniedHandler 接口处理，可以自定义处理逻辑