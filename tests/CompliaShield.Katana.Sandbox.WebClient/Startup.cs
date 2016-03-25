using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(CompliaShield.Katana.Sandbox.WebClient.Startup))]
namespace CompliaShield.Katana.Sandbox.WebClient
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
