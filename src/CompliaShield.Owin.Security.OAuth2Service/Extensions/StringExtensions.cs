
namespace CompliaShield.Owin.Extensions
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Threading.Tasks;

    public static class StringExtensions
    {

        public static string StripTrailingSlashesAll(this string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return string.Empty;
            }
            string strPatternExp = "(/+)$";
            return Regex.Replace(input, strPatternExp, "");
        }

    }
}
