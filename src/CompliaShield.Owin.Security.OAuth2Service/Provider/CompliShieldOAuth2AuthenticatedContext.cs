// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.


namespace CompliaShield.Owin.Security.OAuth2Service
{

    using System;
    using System.Globalization;
    using System.Linq;
    using System.IdentityModel.Tokens;
    using System.Security.Claims;
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;


    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Auth",
        Justification = "OAuth2 is a valid word.")]
    public class CompliaShieldOAuth2AuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="CompliaShieldOAuth2AuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized CompliaShield user info</param>
        /// <param name="accessToken">CompliaShield OAuth 2.0 access token</param>
        /// <param name="refreshToken">Goolge OAuth 2.0 refresh token</param>
        /// <param name="expires">Seconds until expiration</param>
        public CompliaShieldOAuth2AuthenticatedContext(IOwinContext context, string accessToken,
            string refreshToken, string expires)
            : base(context)
        {
            Token = new JwtSecurityToken(accessToken);

            User = JObject.FromObject(Token.Payload);
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            // TODO: Parse these values to be more proper for claims

            this.Id = TryGetValue(User, "id");
            this.Name = TryGetValue(User, "displayName");
            this.GivenName = TryGetValue(User, "name", "givenName");
            this.FamilyName = TryGetValue(User, "name", "familyName");
            this.Profile = TryGetValue(User, "url");
            this.Email = TryGetFirstValue(User, "emails", "value");
        }

        ///// <summary>
        ///// Initializes a <see cref="CompliaShieldOAuth2AuthenticatedContext"/>
        ///// </summary>
        ///// <param name="context">The OWIN environment</param>
        ///// <param name="user">The JSON-serialized CompliaShield user info</param>
        ///// <param name="tokenResponse">The JSON-serialized token response CompliaShield</param>
        //public CompliaShieldOAuth2AuthenticatedContext(IOwinContext context, JObject user, JObject tokenResponse)
        //    : base(context)
        //{
        //    User = user;
        //    TokenResponse = tokenResponse;
        //    if (tokenResponse != null)
        //    {
        //        AccessToken = tokenResponse.Value<string>("access_token");
        //        RefreshToken = tokenResponse.Value<string>("refresh_token");

        //        int expiresValue;
        //        if (Int32.TryParse(tokenResponse.Value<string>("expires_in"), NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
        //        {
        //            ExpiresIn = TimeSpan.FromSeconds(expiresValue);
        //        }
        //    }

        //    Id = TryGetValue(user, "id");
        //    Name = TryGetValue(user, "displayName");
        //    GivenName = TryGetValue(user, "name", "givenName");
        //    FamilyName = TryGetValue(user, "name", "familyName");
        //    Profile = TryGetValue(user, "url");
        //    Email = TryGetFirstValue(user, "emails", "value"); // TODO:
        //}

        /// <summary>
        /// Gets the JWT
        /// </summary>
        /// <remarks>
        /// 
        /// </remarks>
        public JwtSecurityToken Token { get; private set; }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the CompliaShield user obtained from the endpoint https://www.googleapis.com/oauth2/v3/userinfo
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the CompliaShield access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the CompliaShield refresh token
        /// </summary>
        /// <remarks>
        /// This value is not null only when access_type authorize parameter is offline.
        /// </remarks>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the CompliaShield access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the CompliaShield user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the user's given name
        /// </summary>
        public string GivenName { get; set; }

        /// <summary>
        /// Gets the user's family name
        /// </summary>
        public string FamilyName { get; set; }

        /// <summary>
        /// Gets the user's profile link
        /// </summary>
        public string Profile { get; private set; }

        /// <summary>
        /// Gets the user's email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Token response from CompliaShield
        /// </summary>
        public JObject TokenResponse { get; private set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }

        // Get the given subProperty from a property.
        private static string TryGetValue(JObject user, string propertyName, string subProperty)
        {
            JToken value;
            if (user.TryGetValue(propertyName, out value))
            {
                var subObject = JObject.Parse(value.ToString());
                if (subObject != null && subObject.TryGetValue(subProperty, out value))
                {
                    return value.ToString();
                }
            }
            return null;
        }

        // Get the given subProperty from a list property.
        private static string TryGetFirstValue(JObject user, string propertyName, string subProperty)
        {
            JToken value;
            if (user.TryGetValue(propertyName, out value))
            {
                var array = JArray.Parse(value.ToString());
                if (array != null && array.Count > 0)
                {
                    var subObject = JObject.Parse(array.First.ToString());
                    if (subObject != null)
                    {
                        if (subObject.TryGetValue(subProperty, out value))
                        {
                            return value.ToString();
                        }
                    }
                }
            }
            return null;
        }
    }
}
