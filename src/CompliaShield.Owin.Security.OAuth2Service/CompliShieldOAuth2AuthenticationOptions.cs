// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using Microsoft.Owin;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace CompliaShield.Owin.Security.OAuth2Service
{
    /// <summary>
    /// Configuration options for <see cref="CompliaShieldOAuth2AuthenticationMiddleware"/>
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Auth",
        Justification = "OAuth2 is a valid word.")]
    public class CompliaShieldOAuth2AuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        /// Initializes a new <see cref="CompliaShieldOAuth2AuthenticationOptions"/>
        /// </summary>
        public CompliaShieldOAuth2AuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            this.Caption = Constants.DefaultAuthenticationType;
            this.CallbackPath = new PathString("/signin-compliashield");
            this.AuthenticationMode = AuthenticationMode.Passive;
            this.Scope = new List<string>();
            this.BackchannelTimeout = TimeSpan.FromSeconds(60);
            this.OnGetResellerKey = () => Task.FromResult<string>(null);
            this.OnGetBrandKey = () => Task.FromResult<string>(null);
            this.UniqueNameDesignations = new string[] { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" };
        }

        public void AddDefaultUniqueNameDesignation(string value)
        {
            if(this.UniqueNameDesignations == null)
            {
                this.UniqueNameDesignations = new string[] { value };
            }
            else if (!this.UniqueNameDesignations.Contains(value))
            {
                var list = this.UniqueNameDesignations.ToList();
                list.Add(value);
                this.UniqueNameDesignations = list.ToArray();
            }
        }

        /// <summary>
        /// Gets or sets the CompliaShield-assigned client id
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the CompliaShield-assigned client secret
        /// </summary>
        public string ClientSecret { get; set; }

        public string ApprovalPrompt { get; set; }

        /// <summary>
        /// The unique name designation to apply claims identity.
        /// </summary>
        public IEnumerable<string> UniqueNameDesignations { get; set; }

        public IEnumerable<string> RolesDesignations { get; set; }

        public Func<Task<string>> OnGetResellerKey { get; set; }

        public Func<Task<string>> OnGetBrandKey { get; set; }

        /// <summary>
        /// Gets or sets the a pinned certificate validator to use to validate the endpoints used
        /// in back channel communications belong to CompliaShield.
        /// </summary>
        /// <value>
        /// The pinned certificate validator.
        /// </value>
        /// <remarks>If this property is null then the default certificate checks are performed,
        /// validating the subject name and if the signing chain is a trusted party.</remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        /// Gets or sets timeout value in milliseconds for back channel communications with CompliaShield.
        /// </summary>
        /// <value>
        /// The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        /// The HttpMessageHandler used to communicate with CompliaShield.
        /// This cannot be set at the same time as BackchannelCertificateValidator unless the value 
        /// can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        /// Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        /// The request path within the application's base path where the user-agent will be returned.
        /// The middleware will process this request when it arrives.
        /// Default value is "/signin-google".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user <see cref="System.Security.Claims.ClaimsIdentity"/>.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="ICompliaShieldOAuth2AuthenticationProvider"/> used to handle authentication events.
        /// </summary>
        public ICompliaShieldOAuth2AuthenticationProvider Provider { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; set; }

        /// <summary>
        /// access_type. Set to 'offline' to request a refresh token.
        /// </summary>
        public string AccessType { get; set; }
    }
}
