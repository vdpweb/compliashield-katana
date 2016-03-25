
namespace CompliaShield.Owin.Security.OAuth2Service
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json;

    class CompliaShieldOAuthAuthenticatedContext
    {

        [JsonProperty("certserialnumber")]
        public string Certserialnumber { get; set; }

        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("email")]
        public string Email { get; set; }

        [JsonProperty("displayName")]
        public string DisplayName { get; set; }

        [JsonProperty("urn:internal:role")]
        public string[] UrnInternalRole { get; set; }

        [JsonProperty("role")]
        public string[] Role { get; set; }

        [JsonProperty("urn:oauth:scope")]
        public string[] UrnOauthScope { get; set; }

        [JsonProperty("urn:app:client_id")]
        public string UrnAppClientId { get; set; }

        [JsonProperty("urn:app:username")]
        public string AppClientId { get; set; }

        [JsonProperty("urn:app:username")]
        public string AppUsername { get; set; }

        [JsonProperty("iss")]
        public string Iss { get; set; }

        [JsonProperty("aud")]
        public string Aud { get; set; }

        [JsonProperty("exp")]
        public int Exp { get; set; }

        [JsonProperty("nbf")]
        public int Nbf { get; set; }
    }

}

