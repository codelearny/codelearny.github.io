---
title: JWT简介
date: 2021-04-24 09:57:41
tags: [JWT,secure]
categories:
    - [Java,Spring,Spring Security]
    - [Web,JWT]
---
# JSON Web Token
>[官网说明](https://jwt.io/introduction)

## What
`JSON Web Token`（`JWT`）是一个开放标准（[RFC 7519](https://tools.ietf.org/html/rfc7519)），它定义了一种紧凑的、自包含的方式，可以将各方之间的信息作为JSON对象安全地传输。
基于数字签名进行验证，可以使用`HMAC`算法或者基于公钥/私钥对的`RSA`或`ECDSA`进行签名

### structure
`JWT`由三部分构成，由点号（`.`）分割
* Header
* Payload
* Signature

通常由以上三部分组成如下的形式

`xxxx.yyyy.zzzz`

#### Header
`Header`通常由两部分组成：令牌的类型（`JWT`）和使用的签名算法（例如 `HMAC SHA256` 或 `RSA`）
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
然后对这个`JSON`进行`Base64Url`编码形成`JWT`的第一部分

#### Payload
`Payload`包含声明（`claims`）。声明是关于实体（通常是用户）和附加数据的声明。
声明有三种类型：*registered*,*public*,*private*

* **Registered claims**  
这些是一组预定义的声明，它们不是强制性的，而是推荐的，以提供一组有用的、可互操作的声明。
其中一些是：**iss**（发行者）、**exp**（到期时间）、**sub**（主题）、**aud**（受众）和其他。

* **Public claims**  
这些可以由使用`JWT`的人随意定义。但是为了避免冲突，应该在[ IANA JSON Web Token Registry ](https://www.iana.org/assignments/jwt/jwt.xhtml)中定义它们，或者将它们定义为包含防冲突命名空间的URI。

* **Private claims**  
这些是为在同意使用它们的各方之间共享信息而创建的自定义声明，既不是*Registered*，也不是*Public*。
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```
然后对这个`JSON`进行`Base64Url`编码形成`JWT`的第二部分
>请注意，对于已签名的令牌，此信息虽然受到了防篡改保护，但任何人都可以读取。不要将敏感信息放在`JWT`的有`Payload`或`Header`元素中，除非它是加密的。

#### Signature
签名部分由编码的`Header`、编码的`Payload`、一个密钥、报头中指定的算法，并对其进行签名。
```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```
签名用于验证消息在发送过程中没有发生更改，对于使用私钥签名的令牌，它还可以验证`JWT`的发送者是它所说的发送者。

#### Encoded
将以上三部分`Base64-URL`编码的字符串以点号分隔，就得到了最终的令牌

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`

可以使用[ jwt.io Debugger ](https://jwt.io/#debugger-io)进行解码，验证，生成`JWT`

## When

### Authorization
这是使用`JWT`最常见的场景。
一旦用户登录，每个后续请求都将包括`JWT`，允许用户访问该令牌允许的路由、服务和资源。
单点登录是目前广泛使用JWT的一个特性，因为它的开销很小，并且能够很容易地跨不同的域使用。
### Information Exchange
`JWT`是在各方之间安全地传输信息的一种好方法。
因为`JWT`可以签名，例如使用公钥/私钥对，您可以确保发送者的身份。
此外，由于签名是使用`Hader`和`Payload`计算的，因此您还可以验证内容没有被篡改。

## How
在身份验证中，当用户使用其凭据成功登录时，将返回一个`JWT`。因为令牌是凭证，所以必须非常小心地防止安全问题。通常，您不应该将令牌保留的时间超过所需的时间。

每当用户想要访问受保护的路由或资源时，用户代理都应该发送JWT，通常在`Authorization header`中使用`Bearer schema`。标题的内容应如下所示：
```http
Authorization: Bearer <token>
```

在某些情况下，这可以是无状态授权机制。服务器的受保护路由将在`Authorization header`中检查有效的`JWT`，如果存在，则允许用户访问受保护的资源。如果`JWT`包含必要的数据，则可以在一些情况下减少查询数据库的操作。

如果令牌是在`Authorization header`中发送的，不会存在跨源资源共享（`CORS`）问题，因为它不使用`cookies`。

通常的流程如下：
1. 应用程序或客户端向授权服务器请求授权。这是通过不同的授权流之一执行的。例如，一个典型的[ OpenID Connect ](https://openid.net/connect/)兼容web应用程序将通过`/oauth/authorize`端点使用[ authorization code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)。
2. 当授权通过时，授权服务器向应用程序返回一个访问令牌。
3. 应用程序使用访问令牌访问受保护的资源（如`API`）。
>请注意，对于签名令牌，令牌中包含的所有信息都会暴露给用户或其他方，即使他们无法更改它。这意味着您不应该在令牌中放置机密信息。

## Why
让我们讨论一下`JSON Web Token`（`JWT`）与`Simple Web Tokens`（`SWT`）和`Security Assertion Markup Language Tokens`（`SAML`）相比的优势。

由于`JSON`没有`XML`那么冗长，因此当它被编码时，它的大小也更小，这使得`JWT`比`SAML`更紧凑。这使得`JWT`成为在`HTML`和`HTTP`环境中传递的好选择。

安全方面，`SWT`只能使用`HMAC`算法由共享密钥对称签名。但是，`JWT`和`SAML`令牌可以使用`X.509`证书形式的公钥/私钥对进行签名。与签名`JSON`的简单性相比，使用`XML`数字签名来签名`XML`而不引入模糊的安全漏洞是非常困难的。

`JSON`解析器在大多数编程语言中都很常见，因为它们直接映射到对象。相反，`XML`没有自然的文档到对象的映射。这使得使用`JWT`比使用`SAML`断言更容易。

关于使用，`JWT`是在互联网规模上使用的。这突出了`JWT`在多个平台（尤其是移动平台）上客户端处理的方便性。

更多信息[Auth0](http://auth0.com/learn/json-web-tokens?_ga=2.193042795.793010448.1619229222-2061826501.1619229222)