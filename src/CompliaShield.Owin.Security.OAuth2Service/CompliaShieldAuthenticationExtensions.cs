

// OpenID is obsolete
#pragma warning disable 618

using System;
using Microsoft.Owin.Security;
using CompliaShield.Owin.Security.OAuth2Service;
using Owin;

namespace CompliaShield.Owin.Extensions
{
    /// <summary>
    /// Extension methods for using <see cref="CompliaShieldAuthenticationMiddleware"/>
    /// </summary>
    public static class CompliaShieldAuthenticationExtensions
    {
        ///// <summary>
        ///// Authenticate users using CompliaShield OpenId
        ///// </summary>
        ///// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        ///// <param name="options">Middleware configuration options</param>
        ///// <returns>The updated <see cref="IAppBuilder"/></returns>
        //[Obsolete("CompliaShield is discontinuing support for the OpenId. Use OAuth2 instead.", error: false)]
        //public static IAppBuilder UseCompliaShieldAuthentication(this IAppBuilder app, CompliaShieldAuthenticationOptions options)
        //{
        //    if (app == null)
        //    {
        //        throw new ArgumentNullException("app");
        //    }
        //    if (options == null)
        //    {
        //        throw new ArgumentNullException("options");
        //    }

        //    app.Use(typeof(CompliaShieldAuthenticationMiddleware), app, options);
        //    return app;
        //}

        ///// <summary>
        ///// Authenticate users using CompliaShield OpenId
        ///// </summary>
        ///// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        ///// <returns>The updated <see cref="IAppBuilder"/></returns>
        //[Obsolete("CompliaShield is discontinuing support for the OpenId. Use OAuth2 instead.", error: false)]
        //public static IAppBuilder UseCompliaShieldAuthentication(
        //    this IAppBuilder app)
        //{
        //    return UseCompliaShieldAuthentication(
        //        app,
        //        new CompliaShieldAuthenticationOptions());
        //}

        /// <summary>
        /// Authenticate users using CompliaShield OAuth 2.0
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Auth",
            Justification = "OAuth2 is a valid word.")]
        public static IAppBuilder UseCompliaShieldAuthentication(this IAppBuilder app, CompliaShieldOAuth2AuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(CompliaShieldOAuth2AuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using CompliaShield OAuth 2.0
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="clientId">The google assigned client id</param>
        /// <param name="clientSecret">The google assigned client secret</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Auth",
            Justification = "OAuth2 is a valid word.")]
        public static IAppBuilder UseCompliaShieldAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientSecret)
        {
            return UseCompliaShieldAuthentication(
                app,
                new CompliaShieldOAuth2AuthenticationOptions 
                { 
                    ClientId = clientId,
                    ClientSecret = clientSecret
                });
        }
    }
}
#pragma warning restore 618