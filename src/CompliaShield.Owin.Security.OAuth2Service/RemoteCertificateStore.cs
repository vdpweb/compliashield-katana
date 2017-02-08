
namespace CompliaShield.Owin
{
    using Extensions;
    using Newtonsoft.Json;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Runtime.Caching;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;

    public static class RemoteCertificateStore
    {

        #region properties

        private static readonly MemoryCache _cache;
        private const string CachePrefix = "REMOTE_CERTS__";

        #endregion

        #region .ctors

        static RemoteCertificateStore()
        {
            _cache = new MemoryCache("RemoteCertificateRepositoryCache");
        }

        #endregion

        #region methods

        public static async Task<X509Certificate2> GetCertificateAsync(string endpoint, string keyId, bool forceRefresh = false)
        {

            if (string.IsNullOrEmpty(endpoint))
            {
                throw new ArgumentException("endpoint");
            }
            if (string.IsNullOrEmpty(keyId))
            {
                throw new ArgumentException("keyId");
            }

            keyId = keyId.ToLower(); // always just go lower here

            X509Certificate2 cert = null;
            if (!forceRefresh)
            {
                cert = _cache[CachePrefix + keyId] as X509Certificate2;
            }

            if (cert == null)
            {
                // ensure we don't crush the service looking for missing certs
                var notFound = (bool?)_cache[CachePrefix + keyId + "__NOT_FOUND"];
                if (notFound.HasValue)
                {
                    throw new ArgumentOutOfRangeException(string.Format("KeyId '{0}' could not be found in the certificate cache or at the endpoint '{1}'.", keyId, endpoint));
                }

                string publicPem = null;
                using (var client = new HttpClient())
                {
                    client.Timeout = TimeSpan.FromSeconds(10);
                    endpoint = endpoint.StripTrailingSlashesAll() + "/" + keyId + ".cer";
                    client.DefaultRequestHeaders.Accept.Clear();
                    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                    HttpResponseMessage response = null;
                    try
                    {
                        response = await client.GetAsync(endpoint);
                    }
                    catch (Exception ex)
                    {
                        // add to the cache for a minute of the not found
                        _cache.AddOrGetExisting(CachePrefix + keyId + "__NOT_FOUND", true, new CacheItemPolicy() { AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(1) });

                        var outerEx = new HttpRequestException(string.Format("Endpoint '{0}' threw a exception on GetAsync(endpoint).", endpoint), ex);
                        throw outerEx;
                    }
                    if (response.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        publicPem = await response.Content.ReadAsStringAsync();
                    }
                    else if (response.StatusCode == System.Net.HttpStatusCode.NoContent || response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        // add to the cache for a minute of the not found
                        _cache.AddOrGetExisting(CachePrefix + keyId + "__NOT_FOUND", true, new CacheItemPolicy() { AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(1) });
                        throw new ArgumentOutOfRangeException(string.Format("KeyId '{0}' could not be found in the certificate cache or at the endpoint '{1}'.", keyId, endpoint));
                    }
                    else
                    {
                        // cache the data
                        // add to the cache for a minute of the not found
                        _cache.AddOrGetExisting(CachePrefix + keyId + "__NOT_FOUND", true, new CacheItemPolicy() { AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(1) });
                        response.EnsureSuccessStatusCode();
                    }
                }

                if (publicPem == null)
                {
                    throw new InvalidOperationException("publicPem must be populated by this point.");
                }

                var bytes = Encoding.UTF8.GetBytes(publicPem);
                try
                {
                    cert = new X509Certificate2(bytes);
                }
                catch (Exception ex)
                {
                    _cache.AddOrGetExisting(CachePrefix + keyId + "__NOT_FOUND", true, new CacheItemPolicy() { AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(1) });
                    var outerEx = new FormatException(string.Format("X509Certificate2 could not be created from value. Thumbprint '{0}':\r\n{1}", keyId, publicPem), ex);
                    throw outerEx;
                }
            }

            if (cert == null)
            {
                // cache 
                _cache.AddOrGetExisting(CachePrefix + keyId, true, new CacheItemPolicy() { AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(20), Priority = CacheItemPriority.Default });
                throw new InvalidOperationException("cert must be populated by this point.");
            }
            return cert;
        }

        #endregion


    }
}
