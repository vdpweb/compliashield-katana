
namespace CompliaShield.Owin
{
    using Microsoft.Owin.Logging;
    using System;
    using System.Collections.Generic;
    using System.IdentityModel;
    using System.IdentityModel.Tokens;
    using System.Linq;
    using System.Net.Http;
    using System.Runtime.Caching;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Utilities;

    public class JwtSecurityTokenRemoteKeyHandler : JwtSecurityTokenHandler, ISecurityTokenValidator
    {

        private const string SigningCertificateEndpoint = "https://clientservices.compliashield.com/oauth2/v1/certs";
        private const string Issuer = "accounts.compliashield.com";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        private static readonly MemoryCache _cache;

        static JwtSecurityTokenRemoteKeyHandler()
        {
            _cache = new MemoryCache("JwtSecurityTokenRemoteKeyHandler");
        }

        public JwtSecurityTokenRemoteKeyHandler(HttpClient httpClient, ILogger logger) : base()
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public bool ShouldValidateAudience { get; set; }

        private static DateTime _nextUpdateCheckTimeUtc = DateTime.MinValue;

        public Func<IEnumerable<string>, SecurityToken, TokenValidationParameters, Task> OnValidateAudience { get; set; }

        protected override void ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (!this.ShouldValidateAudience)
            {
                return;
            }
            if (this.OnValidateAudience == null)
            {
                base.ValidateAudience(audiences, securityToken, validationParameters);
            }
            else
            {
                this.OnValidateAudience(audiences, securityToken, validationParameters);
            }
        }


        protected override JwtSecurityToken ValidateSignature(string token, TokenValidationParameters validationParameters)
        {
            string keyId;
            var hasSigningKey = this.HasSigningKey(token, validationParameters, out keyId);
            // don't allow no signing key
            if (!hasSigningKey || string.IsNullOrEmpty(keyId))
            {
                var ex = new SignatureVerificationFailedException("Invalid signature.");
                throw ex;
            }

            if (validationParameters.IssuerSigningKeyResolver == null)
            {
                validationParameters.IssuerSigningKeyResolver = (token2, securityToken2, keyIdentifier2, validationParameters2) =>
                {
                    var rsa = AsyncHelper.RunSync(() => this.RemoteEnabledKeyCheckerAsync(token2, securityToken2, keyIdentifier2, validationParameters2, keyId));
                    if (rsa == null)
                    {
                        var ex = new SignatureVerificationFailedException(string.Format("No valid certificate could be found with thumbprint '{0}' at endpoint '{1}'.", keyId, SigningCertificateEndpoint));
                        throw ex;
                    }
                    return new RsaSecurityKey(rsa);
                };
            }

            JwtSecurityToken jwtSecurityToken = null;
            try
            {
                jwtSecurityToken = base.ValidateSignature(token, validationParameters);
            }
            catch (SignatureVerificationFailedException ex)
            {
                if (_nextUpdateCheckTimeUtc < DateTime.UtcNow)
                {

                }
                var exTypeName = ex.GetType().FullName;
                throw ex;
            }

            // ensure that the alg is valid to our RS256 requirement
            if (jwtSecurityToken.SignatureAlgorithm != "RS256")
            {
                var ex = new SignatureVerificationFailedException(string.Format("SignatureAlgorithm RS256 is required. SignatureAlgorithm was '{0}'.", jwtSecurityToken.SignatureAlgorithm));
                jwtSecurityToken = null;
                throw ex;
            }

            return jwtSecurityToken;
        }

        private async Task<RSA> RemoteEnabledKeyCheckerAsync(string token, SecurityToken securityToken, SecurityKeyIdentifier keyIdentifier, TokenValidationParameters validationParameters, string keyId)
        {
            if (!(securityToken is JwtSecurityToken))
            {
                throw new ArgumentException("securityToken must be of type JwtSecurityToken");
            }

            var jwtSecurityToken = (JwtSecurityToken)securityToken;
            var issuer = jwtSecurityToken.Issuer;

            X509Certificate2 cert = null;
            if (issuer == Issuer || issuer == "https://" + Issuer)
            {
                var rsa = _cache["RSA__" + keyId] as RSACryptoServiceProvider;
                if (rsa == null && _cache["RSA__" + keyId + "__NOT_FOUND"] == null)
                {
                    return null;
                }
                try
                {
                    cert = await RemoteCertificateStore.GetCertificateAsync(SigningCertificateEndpoint, keyId);
                    return cert.PublicKey.Key as RSACryptoServiceProvider;
                }
                catch (Exception ex)
                {
                    if(_logger != null)
                    {
                        _logger.WriteError("JwtSecurityTokenRemoteKeyHandler.RemoteEnabledKeyChecker failed: " + ex.GetType().FullName + ":" + ex.Message, ex);
                    }
                }
            }
            return null;
        }

        private bool HasSigningKey(string token, TokenValidationParameters validationParameters, out string keyId)
        {
            keyId = null;
            var thumbprints = new List<string>();
            if (validationParameters != null && validationParameters.IssuerSigningTokens != null)
            {
                foreach (var item in validationParameters.IssuerSigningTokens)
                {
                    if (item is X509SecurityToken)
                    {
                        var x509Token = (X509SecurityToken)item;
                        if (x509Token.Certificate != null && !string.IsNullOrEmpty(x509Token.Certificate.Thumbprint))
                        {
                            var thumbprintLower = x509Token.Certificate.Thumbprint.ToLower();
                            if (!thumbprints.Contains(thumbprintLower))
                            {
                                thumbprints.Add(thumbprintLower);
                            }
                        }
                    }
                }
            }

            JwtSecurityToken securityToken = this.ReadToken(token) as JwtSecurityToken;

            var checkVal = securityToken.Header.SigningKeyIdentifier;

            if (securityToken.Header.ContainsKey("kid"))
            {
                var keyIdToLower = securityToken.Header["kid"].ToString().ToLower();
                keyId = keyIdToLower;
                if (thumbprints.Contains(keyIdToLower))
                {
                    return true;
                }
            }
            if (securityToken.Header.ContainsKey("keyid"))
            {
                var keyIdToLower = securityToken.Header["keyid"].ToString().ToLower();
                keyId = keyIdToLower;
                if (thumbprints.Contains(keyIdToLower))
                {
                    return true;
                }
            }
            return false;
        }

    }
}
