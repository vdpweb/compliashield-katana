using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;

namespace CompliaShield.Katana.Sandbox.WebClient
{
    public static class IdentityHelpers
    {
        public static string GetUserEmail(this IIdentity identity)
        {
            if (identity == null)
            {
                throw new ArgumentNullException("identity");
            }
            ClaimsIdentity identity2 = identity as ClaimsIdentity;
            if (identity2 != null)
            {
                return identity2.FindFirstValue("email");
            }
            return null;
        }

        public static string FindFirstValue(this ClaimsIdentity identity, string claimType)
        {
            if (identity == null)
            {
                throw new ArgumentNullException("identity");
            }
            Claim claim = identity.FindFirst(claimType);
            if (claim == null)
            {
                return null;
            }
            return claim.Value;
        }
    }
}