### Session, cookie, JWT, token, SSO, and OAuth 2.0

These are various mechanism to maintain the user identity

**Authentication** verifies the identity of a user or service, and   
**Authorization** determines their access rights. 


Consider a website login, eg gmail, which takes in UserName and Password. This is the **HTTP Basic Authentication**

This once validated, it uses the **Session + Cookie mechanism** to maintain the login.  
The server stores the **Session**, while the browser stores the **SessionID in a Cookie** which is sent with each request.

**Cookies** are mainly used for three purposes:
* Session management: Logins, shopping carts, game scores, or anything else the server should remember
* Personalization: User preferences, themes, and other settings
* Tracking: Recording and analyzing user behavior

### Cookies
After receiving an HTTP request, a server can send one or more _Set-Cookie headers_ with the response. The browser usually stores the cookie and sends it with requests made to the same server inside a _Cookie HTTP header_  
The server can specify an expiration date or time period after which the cookie shouldn't be sent. 

eg. Consider the following server response
```text
HTTP/2.0 200 OK
Content-Type: text/html
Set-Cookie: id=a3fWa; Expires=Thu, 21 Oct 2021 07:28:00 GMT; Secure; HttpOnly
```
This specifies
* The Cookie with id=a3fWa will send on each subsequent request till expiry
* With the **Expires** date and time, the cookie will be expired relative to the client time, not the server
* A cookie with the **Secure** attribute is only sent to the server with an **encrypted** request over the HTTPS protocol. It's never sent with unsecured HTTP (except on localhost), which means man-in-the-middle attackers can't access it easily
* A cookie with the **HttpOnly** attribute is **inaccessible to the JavaScript Document.cookie** API; it's only sent to the server. For example, cookies that persist in server-side sessions don't need to be available to JavaScript and should have the HttpOnly attribute. **This precaution helps mitigate cross-site scripting (XSS) attacks**.


This mechanism worked well in the pre-mobile world, when we mainly used browsers to access the internet.  
However, with the advent of mobile computing, a better mechanism was needed, since we have applications other than browsers making HTTP requests.  
Enter Tokens

### Tokens
Instead of looking up the session_id in the database, for each request, the server could generate a token that has the claim eg "logged in as administrator" and provide that to a client.  
The client could then use that token to prove that it is logged in as admin. 

The tokens can be signed by server's private key, so that the server decrypts and verifies that the token is legitimate.  
However, if client wants to verify the token's legitimacy, it can use the public key, **if available**.

From what we see above, each server can have its own mechanism to encrypt tokens. A standardization was needed.  
**Enter JWT**

### JWT Tokens (JSON Web Tokens)
JWT is a standard way of representing tokens. This information can be verified and trusted because it is digitally signed. Since JWT contains the signature, there is no need to save session information on the server side.

![img](imgs/jwt_token.png)

#### JWT Structure

||||
|---|---|---|
| **Header** | Identifies which algorithm is used to generate the signature <br> typical cryptographic algorithms used are HMAC with SHA-256 (HS256) and RSA signature with SHA-256 (RS256).| {<br>&nbsp;&nbsp; "alg": "HS256", <br> &nbsp;&nbsp; "typ": "JWT"<br>} | 
|**Payload** | Contains a set of claims. eg, Issued At Time claim (iat) and a custom claim (loggedInAs). | {<br>&nbsp;&nbsp; "loggedInAs": "admin", <br>&nbsp;&nbsp; "iat": 1422779638 <br>}|
|**Signature**| Securely validates the token. The signature is calculated by encoding the header and payload using Base64url Encoding and concatenating the two together with a period separator. That string is then run through the cryptographic algorithm specified in the header.| HMAC_SHA256(<br/>&nbsp;&nbsp; secret,<br/>&nbsp;&nbsp; base64urlEncoding(header) + '.' +  base64urlEncoding(payload)<br>)|


The three parts are encoded separately using Base64url Encoding, and concatenated using periods to produce the JWT:
```
const token = base64urlEncoding(header) + '.' + base64urlEncoding(payload) + '.' + base64urlEncoding(signature)
```

**Remember the JWT is signed, but not encrypted, everyone can read its contents, but when you don't know the private key, you can't change it. The receiver can however check if the message has changed by matching the signature**


In authentication, when the user successfully logs in using their credentials, a JSON Web Token will be returned and must be saved locally (typically in local or session storage, but cookies can also be used), instead of the traditional approach of creating a session in the server and returning a cookie. 


As we are living in microservices world, the services also need to authenticate/authorize between each other

![img](imgs/jwt.png)

With JWT, the microservice has to perform two steps mainly
* **Generating the JSON Web Token** This is the authentication part, where in the user is validated, and the payload is added with user id, expiration date etc and also user roles and user-defined information.
* **Validating the token for received requests** This is the authorization part, where the Base64 JWT token is decrypted, expiry checked, and the request is processed/not processed based on the user id and roles in the token

|What happens if JWT is stolen?|
|---|
| Because JWTs are used to identify the client, if one is stolen or compromised, an attacker has full access to the user’s account in the same way they would if the attacker had instead compromised the user’s username and password.  |
| **BUT**, there is one thing that makes a stolen JWT slightly less bad than a stolen username and password: timing. Because **JWTs can be configured to automatically expire after a set amount of time** (a minute, an hour, a day, whatever), attackers can only use your JWT to access the service until it expires.|
| **BUT**, the actual problem here is that if an attacker was able to steal your token in the first place, they’re likely able to do it once you get a new token as well. The most common ways this happens is by man-in-the-middling (MITM) your connection or getting access to the client or server directly. And unfortunately, in these scenarios, even the shortest-lived JWTs won’t help you at all. |
| So, we should treat JWTs like password, and never publicly share them. **Also, we should never store the tokens in HTML5 Local Storage and instead store them in server-side cookies** (described above) that are not accessible to JavaScript.|


Now our API or the server still has to maintain a user credentials database. Each user of our website/app has to sign up, the server needs to secure the password of the user, rotate password, etc.   
To Ease these repetitive and error-prone tasks, we have Single Sign-On 

# Single Sign-On (SSO)
We can leverage Single Sign-on instead of JWT, where the user is authenticated with a third-party SSO server, and passes in the token to our service.  
The service in turn validates the token with the SSO server before granting access.  
Needless to say, this results in a lot of trivial network traffic, repeated work, and it may cause single point of failure.

![img](imgs/sso.png)

Single sign-on (SSO) has evolved quietly into federated authentication. Federated authentication streamlines user login credentials across multiple platforms and applications to simplify the sign-in process while enhancing security.

Security Assertion Markup Language (SAML) and Open Authorization (OAuth) have emerged as the go-to technologies for federated authentication. While SAML is an Extensible Markup Language (XML)-based standard, OAuth is based on JavaScript Object Notation (JSON), binary, or even SAML formats.

**SAML is for User Authentication, OAuth is for User Authorization** 

### How SAML works – the authentication workflow

1. An end user clicks on the “Login” button on a file sharing service at example.com. The file sharing service at example.com is the Service Provider, and the end user is the Client.
2. To authenticate the user, example.com constructs a SAML Authentication Request, signs and optionally encrypts it, and **sends it directly to the IdP** (eg. Google, Facebook, Apple, AWS which manage user authentication). The IdP verifies the received SAML Authentication Request and, if valid, presents a login form for the end user to enter their username and password.
3. The Service Provider redirects the Client’s browser to the IdP for authentication. Once the Client has successfully logged in, the IdP generates a SAML Assertion (also known as a SAML Token), which includes the user identity (such as the username entered before), and sends it directly to the Service Provider.
4. The IdP redirects the Client back to the Service Provider.
5. The Service Provider verifies the SAML Assertion, extracts the user identity from it, assigns correct permissions for the Client and then logs them into the service.

![img](imgs/SAML_flow-768x509.png)

Note that the Service Provider never processed or even saw the Client’s credentials. Here we succeeded logging in with two redirects.  
However, **in mobile applications, handling these redirects is an issue due to the length of HTTP Redirect URL, that's why OAuth is preferred over SAML**

### How OAuth works – the authorization workflow

1. An end user clicks on the “Login” button on a file sharing service at example.com. The file sharing service at example.com is the Resource Server, and the end user is the Client.
2. The Resource Server presents the Client with an Authorisation Grant, and redirects the Client to the Authorisation Server
3. The Client requests an Access Token from the Authorisation Server using the Authorisation Grant Code
4. The Client logs in to the Authorisation Server, and if the code is valid, the Client gets an Access Token that can be used request a protected resource from the Resource Server
5. After receiving a request for a protected resource with an accompanying Access Token, the Resource Server verifies the validity of the token directly with the Authorisation Server
6. If the token was valid, the Authorisation Server sends information about the Client to the Resource Server

![img](imgs/OAuth_flow-768x545.png)

So No Redirects as in case of SAML, but some extra round trip to the Authorization Server.  

The difference between SAML and OAuth should be apparent now:  
 SAML Assertions contain the **signed user identification information**, while with OAuth the Resource Server **needs to make additional round trip in order to authenticate the Client** with the Authorization Server.


### So how to choose between SAML authentication and OAuth?
Good news: one can always use both. The SAML Assertion can be used as an OAuth Bearer Token to access the protected resource.

### What is OpenID Connect (OIDC)
OIDC extends the OAuth protocol so that client services (your applications) verify user identities and exchange profile information through OpenID providers (essentially authentication servers) via RESTful APIs that dispatch JSON web tokens (JWTs) to share information during the authentication process. 
As per my understanding, instead of dealing with XML and assertions in SAML, developers can use JSON Web Tokens.

### OAuth vs OpenID Connect
The OAuth 2.0 framework explicitly does not provide any information about the user that has authorized an application. OAuth 2.0 is a delegation framework, allowing third-party applications to act on behalf of a user, without the application needing to know the identity of the user.

OpenID Connect takes the OAuth 2.0 framework and adds an identity layer on top. It provides information about the user, as well as enables clients to establish login sessions. While this chapter is not meant to be a complete guide to OpenID Connect, it is meant to clarify how OAuth 2.0 and OpenID Connect relate to each other.

https://developer.okta.com/blog/2019/01/23/nobody-cares-about-oauth-or-openid-connect
https://developer.okta.com/blog/2019/10/21/illustrated-guide-to-oauth-and-oidc

## SAML vs OAuth vs OpenID vs SSO. when to use what 
The choice between SAML, OAuth, OpenID, and SSO depends on the authentication and authorization requirements of your application. Here’s a breakdown of when to use each:

1. SAML (Security Assertion Markup Language)  
Use SAML when:
    - You need **Single Sign-On (SSO)** for enterprise applications (e.g., accessing multiple apps after logging in once).
    - You're dealing with **older enterprise systems** that don't support OAuth.
    - Your app integrates with corporate identity providers like Okta, Azure AD, or ADFS.
    - The main goal is **authentication (verifying who the user is).**
    - You work with **XML-based identity assertions.**

    Example Use Case: An employee logs into their company portal, and SAML allows them to access Salesforce, Workday, and other apps without logging in again.

2. OAuth (Open Authorization)  
Use OAuth when:
    - You need to grant **third-party applications** access to user data without sharing credentials.
    - Your app needs **authorization** (not just authentication) to access protected resources (APIs, user profiles, files, etc.).
    - You're working with **mobile or web apps** that need to authenticate users via external services (e.g., Google, Facebook).
    - You need **support for modern token-based authentication (JWTs).**

    Example Use Case: A mobile app requests permission to access a user’s Google Drive files without asking for their Google password.

3. OpenID Connect (OIDC)  
Use OpenID Connect when:
    * You need a modern, OAuth-based **authentication system**.
    * Your app needs **user identity verification in a RESTful JSON format** (instead of XML like SAML).
    * You want to use **social logins** (e.g., Google, Facebook, Microsoft).
    * Your app needs **ID Tokens (JWTs)** for session management.
    * You're working with **web, mobile, or API-driven applications**.

    Example Use Case: A user logs into a third-party app using their Google account via “Sign in with Google”, which returns an ID token verifying their identity.

4. SSO (Single Sign-On)  
    * SSO is a concept, not a protocol
    * SSO can be implemented using SAML, OAuth, or OpenID Connect, depending on the use case.

Example Use Case:
* **Enterprise SSO**: A corporate employee logs in once and gets access to multiple internal applications (typically SAML-based).
* **Social SSO**: A user logs into multiple third-party apps using their Google or Facebook account (typically OpenID Connect-based).



### GDPR and cookies
The **GDPR (General Data Protection Regulation)** is a set of privacy laws established by the **European Union (EU)** to protect the personal data and privacy of EU citizens. When it comes to cookies, the GDPR has specific requirements about how websites handle them, as cookies can collect personal information or track users in ways that can impact privacy.  
Under the GDPR, cookies that are used for tracking or collecting personal data require the explicit consent of the user before they are set.
1. **Prior Consent**: Websites must ask for consent before placing cookies on a user's device, except for cookies that are strictly necessary for the functioning of the site (e.g., session cookies for login).
2. **Clear Information**: The website must inform users about the cookies being used and their purpose (e.g., tracking, analytics, etc.). This is typically done through a cookie banner or pop-up.
3. **Granular Consent**: Users should be able to give granular consent for specific types of cookies (e.g., functional cookies, analytics cookies, advertising cookies) and should be able to withdraw consent easily.```

##### Necessary vs. Non-Essential Cookies
The GDPR makes a distinction between necessary cookies and non-essential cookies:
1. **Necessary cookies:** These are essential for the basic operation of the website (e.g., authentication, cart functionality). **Consent is not required for these cookies, but users should still be informed about their usage**.
2. **Non-essential cookies:** These include cookies used for tracking, advertising, or analytics. Consent is required before setting these cookies.


### What is Keycloak?
Keycloak, an **open source** identity and access management tool for modern web applications, is one approach to **securing command-line apps.**   
Keycloak provides
* Identity and Access Management
* SSO which allows users to securely log into multiple applications using a single set of credentials.
* MFA which enhances the security level by requiring the user to provide two or more factors as proof of identity. eg Facial Recogniton, or OTPs
* Identity Provider (IdP) which is the service used to authenticate the user. That means, you can create users also in keycloak
* It also comes with a web-based GUI that makes things simple to use.

##### Keycloak realms
A Keycloak realm is an isolated management space that maintains a set of users, credentials, roles, and groups. By default, Keycloak has the master realm, whose sole purpose is to create and manage other realms in the system. Additional realms need to be created for application-based use. Configurations and users are specific to a realm.

Each realm can support multiple clients. A Keycloak client represents an application or web service that uses Keycloak to authenticate and authorize users.

##### Keycloak client configuration
To secure apps with Keycloak, you need to have a little knowledge of Keycloak client configuration. Below are a few essential configurations. to provide you a basic idea of how they work. To learn more, use the admin console, where each property is described by help text.

![img](imgs/keycloak.png)

Keycloak allows the use of popular social identity providers, including Google, Facebook, LinkedIn, Instagram, Microsoft, Twitter, and GitHub. These can be configured at the realm level. To use them, the user must retrieve their client ID and client secret from the social media account. For example, to use the GitHub identity provider, you need to create a new OAuth app from GitHub's developer settings to generate a Client ID and Client Secret. The redirect URI should be specified in both Keycloak and the OAuth app.

##### Keycloak authentication
Public applications secured with Keycloak rely on browsers to authenticate users. Things can get tricky when a command-line app involves a browser login. The easiest way might seem to be a copy-paste authentication token, passing it as an argument with the CLI. This approach gets problematic because the credentials are stored in the terminal's history. Moreover, best practice states that users should authenticate using the authorization server's web page.

Instead, to handle command-line application authentication, first, the app needs to build the URL for the authorization server and open it using a browser. The URL is created by transposing Keycloak configurations. The URL looks roughly like this:
```
${keycloakURL}/realms/{realm}/protocol/openid-connect/auth?client_id=${clientID}&redirect_uri=${redirectURI}&response_type=code
````
Once the login page is ready, a lightweight embedded server runs concurrently to handle the redirection. The redirection URI you use must be registered with the client configuration. The redirection URI will have a code as a URL parameter. The embedded server should parse the code to obtain authorization codes by requesting the OpenID connect token endpoint. Then the server needs to be stopped, and control must be transferred back to the script.  
The authorization codes need to be stored in a configuration file. A preferred location is XDG_CONFIG_HOME, which should store user-specific configuration files.

### Open source Projects 
* ZITADEL(https://github.com/zitadel/zitadel) combines the ease of Auth0 with the versatility of Keycloak,  providing you with a wide range of out of the box features to accelerate your project. Multi-tenancy with branding customization, secure login, self-service, OpenID Connect, OAuth2.x, SAML2, Passwordless with FIDO2 (including Passkeys), OTP, U2F, and an unlimited audit trail is there for you, ready to use.

# Use API Gateway with Cognito

When API Gateway uses an Amazon Cognito token for authentication, **it validates the token locally without directly communicating with Amazon Cognito to verify that the token belongs to the same AWS account**. Here's how it works:


### How API Gateway Validates Tokens
1. **Decoding the Token:**
    - API Gateway decodes the JSON Web Token (JWT) using the **public key from the JWKS (JSON Web Key Set) endpoint of the Cognito User Pool**. This public key is specific to the User Pool and can be used to validate tokens issued by that User Pool.
2. **Validating the Token:**
    - API Gateway checks:
        - The **signature** of the token to confirm it is issued by the corresponding Cognito User Pool.
        - The **issuer (iss) claim**, which should match the User Pool's URL (e.g., https://cognito-idp.<region>.amazonaws.com/<user_pool_id>).
        - The **audience (aud) claim**, which should match the app client ID associated with the User Pool.
        - The **expiration (exp) claim**, ensuring the token is still valid.
    
### No Communication with Cognito
- API Gateway does not call Cognito to verify the token's validity or confirm that it belongs to the same AWS account.
- Validation is purely based on the token's signature and claims. As long as the token is valid and meets the above criteria, API Gateway will allow access.

### Implications
- If the token is forged but contains the correct signature and claims, it will pass validation. However, forging a token is practically impossible if the private key of the User Pool is secure.
- Revocation or invalidation of tokens (e.g., if a user is disabled in the User Pool) **is not checked by API Gateway**. This is because API Gateway doesn't interact with Cognito at runtime. To handle such cases, you might need additional custom logic in your backend.

### How to Enhance Security
1. **Use Short-Lived Tokens:** Configure access tokens to have a short TTL (Time-To-Live) to minimize risk.
2. **Custom Authorizers:**
    - You can implement a Lambda authorizer in API Gateway to perform additional checks, such as querying Cognito to confirm the token is still valid and belongs to the correct AWS account.
3. **Regularly Rotate App Client Secrets:** Ensure app client secrets used by your User Pool are securely stored and rotated periodically.

This design avoids unnecessary calls to Cognito, improving performance and scalability, but shifts the responsibility for additional security checks to the developer if needed.

