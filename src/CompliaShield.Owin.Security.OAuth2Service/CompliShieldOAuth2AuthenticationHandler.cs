// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace CompliaShield.Owin.Security.OAuth2Service
{
    internal class CompliaShieldOAuth2AuthenticationHandler : AuthenticationHandler<CompliaShieldOAuth2AuthenticationOptions>
    {

        private const string TokenEndpoint = "https://accounts.compliashield.com/oauth2/token";
        private const string AuthorizeEndpoint = "https://accounts.compliashield.com/oauth2/auth";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;


        public CompliaShieldOAuth2AuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {

            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>();
                body.Add(new KeyValuePair<string, string>("grant_type", "authorization_code"));
                body.Add(new KeyValuePair<string, string>("code", code));
                body.Add(new KeyValuePair<string, string>("redirect_uri", redirectUri));
                body.Add(new KeyValuePair<string, string>("client_id", Options.ClientId));
                body.Add(new KeyValuePair<string, string>("client_secret", Options.ClientSecret));

                // Request the token
                HttpResponseMessage tokenResponse =
                    await _httpClient.PostAsync(TokenEndpoint, new FormUrlEncodedContent(body));

                Exception exception = null;
                try
                {
                    tokenResponse.EnsureSuccessStatusCode();
                }
                catch (Exception ex)
                {
                    exception = ex;

                }
                if (exception != null)
                {
                    string errorText = null;
                    // this is here to read the exception message into the log for more info
                    try
                    {
                        errorText = await tokenResponse.Content.ReadAsStringAsync();
                    }
                    catch { }
                    if (!string.IsNullOrEmpty(errorText))
                    {
                        var oauthEx = new HttpRequestException("Failed to authorize: " + errorText, exception);
                        throw oauthEx;
                    }
                    throw exception;
                }

                // read the regular text here
                string text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                JObject response = JObject.Parse(text);
                string accessToken = response.Value<string>("access_token");

                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                var expires = response.Value<string>("expires_in"); // differs from Google in that it is expressed as expire_in

                // Future: If scopes for profiles, etc. are present retreive more info 
                var context = new CompliaShieldOAuth2AuthenticatedContext(Context, accessToken, null, expires);

                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    CompliaShield.Owin.Security.OAuth2Service.Constants.DefaultAuthenticationType,
                    ClaimTypes.Role);

                // important for IdentityExtensions GetUserId and GetUserName
                
                // get Id claim
                var idClaim = context.Token.Claims.FirstOrDefault(x => x.Type == "id");
                if (idClaim != null)
                {
                    if (Options.UniqueNameDesignations != null && Options.UniqueNameDesignations.Any())
                    {
                        foreach (var desig in Options.UniqueNameDesignations)
                        {
                            context.Identity.AddClaim(new Claim(desig, context.Id, idClaim.ValueType, CompliaShield.Owin.Security.OAuth2Service.Constants.DefaultAuthenticationType, idClaim.Issuer));
                        }
                    }
                }

                foreach (var claim in context.Token.Claims)
                {
                    bool handled = false;

                    // transfer role designations
                    if (this.Options.RolesDesignations != null && this.Options.RolesDesignations.Any())
                    {
                        if (this.Options.RolesDesignations.Contains(claim.Type))
                        {
                            var newClaim = new Claim(ClaimTypes.Role, claim.Value, claim.ValueType, CompliaShield.Owin.Security.OAuth2Service.Constants.DefaultAuthenticationType, idClaim.Issuer);
                            context.Identity.AddClaim(newClaim);
                            handled = true;
                        }
                    }
                    if (!handled)
                    {
                        context.Identity.AddClaim(claim);
                    }
                }

                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                var queryStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                queryStrings.Add("response_type", "code");
                queryStrings.Add("client_id", this.Options.ClientId);
                queryStrings.Add("redirect_uri", redirectUri);

                // space separated
                // CompliaShield OAuth 2.0 asks for non-empty scope. If user didn't set it, set default scope to 
                // "openid email" to get basic user information.
                string scope = "openid email";

                if (this.Options.Scope != null && this.Options.Scope.Any())
                {
                    scope = string.Join(" ", this.Options.Scope);
                }
                AddQueryString(queryStrings, properties, "scope", scope);

                AddQueryString(queryStrings, properties, "access_type", this.Options.AccessType);
                AddQueryString(queryStrings, properties, "approval_prompt", this.Options.ApprovalPrompt);
                AddQueryString(queryStrings, properties, "login_hint");

                // check for the reseller key
                var resellerKey = this.Options.OnGetResellerKey().Result;
                if (!string.IsNullOrEmpty(resellerKey))
                {
                    AddQueryString(queryStrings, properties, "rsl", resellerKey);
                }

                // check for the brand key
                var brandKey = this.Options.OnGetBrandKey().Result;
                if (!string.IsNullOrEmpty(brandKey))
                {
                    AddQueryString(queryStrings, properties, "brand", brandKey);
                }

                string state = Options.StateDataFormat.Protect(properties);
                queryStrings.Add("state", state);

                string authorizationEndpoint = WebUtilities.AddQueryString(AuthorizeEndpoint,
                    queryStrings);

                var redirectContext = new CompliaShieldOAuth2ApplyRedirectContext(
                    Context, Options,
                    properties, authorizationEndpoint);
                Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                // TODO: error responses

                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new CompliaShieldOAuth2ReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;

                if (ticket != null)
                {
                    context.RedirectUri = ticket.Properties.RedirectUri;
                }
                await Options.Provider.ReturnEndpoint(context);



                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }

        private static void AddQueryString(IDictionary<string, string> queryStrings, AuthenticationProperties properties,
            string name, string defaultValue = null)
        {
            string value;
            if (!properties.Dictionary.TryGetValue(name, out value))
            {
                value = defaultValue;
            }
            else
            {
                // Remove the parameter from AuthenticationProperties so it won't be serialized to state parameter
                properties.Dictionary.Remove(name);
            }

            if (value == null)
            {
                return;
            }

            queryStrings[name] = value; //System.Uri.EscapeDataString(value); //System.Net.WebUtility.UrlEncode(value);
        }
    }
}
