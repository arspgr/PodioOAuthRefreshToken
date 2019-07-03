using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PodioOAuthRefreshToken.DAL.Podio.Settings;
using PodioOAuthRefreshToken.HttpClients;
using Newtonsoft.Json.Linq;
using Task = System.Threading.Tasks.Task;

namespace PodioOAuthRefreshToken.Extensions
{
    public static class ServiceCollectionExtension
    {
        public static void AddPodioAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            var clientId = configuration["PodioSettings:ClientId"];
            var clientSecret = configuration["PodioSettings:ClientSecret"];

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = "Podio";
                })
                .AddCookie(options =>
                {
                    options.Cookie.Name = "PodioOAuthRefreshToken";
                    options.Events = new CookieAuthenticationEvents
                    {
                        OnValidatePrincipal = async cookieContext =>
                        {
                            var now = DateTimeOffset.UtcNow;
                            var tokens = cookieContext.Properties.GetTokens().ToList();

                            var expires = tokens.SingleOrDefault(token => token.Name == "expires_at");
                            if (expires == null)
                            {
                                return;
                            }

                            var tokenExpires = DateTimeOffset.Parse(expires.Value);
                            if (tokenExpires < now)
                            {
                                try
                                {
                                    var refreshToken = tokens.SingleOrDefault(token => token.Name == "refresh_token") ??
                                                       throw new Exception("refresh_token is null");

                                    var client = new PodioTokenClient(clientId, clientSecret, refreshToken.Value);

                                    var resp = await client.RefreshToken();

                                    var accessToken = tokens.SingleOrDefault(token => token.Name == "access_token") ??
                                                      throw new Exception("refresh_token is null");

                                    accessToken.Value = resp.AccessToken;
                                    refreshToken.Value = resp.RefreshToken;
                                    var newExpires = DateTimeOffset.UtcNow +
                                                     TimeSpan.FromSeconds(long.Parse(resp.ExpiresIn));
                                    expires.Value = newExpires.ToString("o", CultureInfo.InvariantCulture);

                                    cookieContext.Properties.StoreTokens(tokens);
                                    cookieContext.ShouldRenew = true;
                                }
                                catch (Exception)
                                {
                                    cookieContext.RejectPrincipal();
                                    throw;
                                }
                            }
                        }
                    };
                })
                .AddOAuth("Podio", options =>
                {
                    options.ClientId = clientId;
                    options.ClientSecret = clientSecret;
                    options.Scope.Add("app:read");
                    options.CallbackPath = "/signin-podio";
                    options.AuthorizationEndpoint = "https://podio.com/oauth/authorize";
                    options.TokenEndpoint = "https://podio.com/oauth/token";
                    options.SaveTokens = true;

                    options.Events = new OAuthEvents
                    {
                        OnCreatingTicket = context =>
                        {
                            var user = context.TokenResponse.Response.Value<JObject>("ref");
                            var userId = user.Value<string>("id");

                            if (string.IsNullOrEmpty(userId))
                            {
                                context.Fail("ref -> id is null");
                                return Task.CompletedTask;
                            }

                            context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId,
                                ClaimValueTypes.String, context.Options.ClaimsIssuer));

                            return Task.CompletedTask;
                        }
                    };
                });
        }
    }
}