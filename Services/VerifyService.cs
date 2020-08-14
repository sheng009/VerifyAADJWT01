using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using VerifyAADJWT01.Constraint;

namespace VerifyAADJWT01.Services
{
    /// <summary>
    /// 验证JWT服务
    /// </summary>
    public class VerifyService
    {
        private readonly string _mySecret;
        private SymmetricSecurityKey _mySecretKey;
        private IMemoryCache _memoryCache;

        public VerifyService(string mySecret, IMemoryCache memoryCache)
        {
            _mySecret = mySecret;
            _mySecretKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_mySecret));
            _memoryCache = memoryCache;
        }

        /// <summary>
        /// 从JWT中获取一个claim
        /// </summary>
        /// <param name="token"></param>
        /// <param name="claimType"></param>
        /// <returns></returns>
        public string GetClaim(string token, string claimType)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.ReadJwtToken(token);

            return securityToken.Claims.FirstOrDefault(c => c.Type == claimType)?.Value;
        }

        /// <summary>
        /// 从JWT中获取多个claims
        /// </summary>
        /// <param name="token"></param>
        /// <param name="claimTypes"></param>
        /// <returns></returns>
        public Dictionary<string, string> GetClaims(string token, List<string> claimTypes)
        {
            if (claimTypes == null || claimTypes.Count == 0)
            {
                return null;
            }

            Dictionary<string, string> claimDic = new Dictionary<string, string>();
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.ReadJwtToken(token);

            foreach (var claimType in claimTypes)
            {
                claimDic.Add(claimType, securityToken.Claims.FirstOrDefault(c => c.Type == claimType)?.Value);
            }
            return claimDic;
        }

        /// <summary>
        /// Validate Azure AD JWT for custom applications
        /// </summary>
        /// <param name="token"></param>
        /// <param name="tenantId"></param>
        /// <param name="stsDiscoveryEndpoint"></param>
        /// <param name="signingKeys"></param>
        /// <param name="validateLifetime">也可以在VerifyService.ValidateJWTExpirationTime方法中，验证过期时间</param>
        /// <returns></returns>
        public bool ValidateAADJWT(string token, string tenantId, string stsDiscoveryEndpoint, ICollection<SecurityKey> signingKeys, bool validateLifetime)
        {
            IdentityModelEventSource.ShowPII = true;
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateLifetime = validateLifetime,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = $"https://sts.windows.net/{tenantId}/",
                ValidAudience = "api://faa0afb8-bfe5-4648-82e9-c6f3b909fcf4",
                IssuerSigningKeys = signingKeys
            };
            var tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                var result = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken jwt);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{Environment.NewLine}{Environment.NewLine}");
                Console.WriteLine($"[Token Validation Error]: {ex.Message}");
                Console.WriteLine($"{Environment.NewLine}{Environment.NewLine}");
                return false;
            }

            return true;
        }

        /// <summary>
        /// 获取public key去验证JWT签名
        /// </summary>
        /// <param name="stsDiscoveryEndpoint"></param>
        /// <param name="token"></param>
        /// <param name="tenantId"></param>
        /// <param name="clientId"></param>
        /// <returns></returns>
        public ICollection<SecurityKey> GetSigningKeys(string stsDiscoveryEndpoint, string token, string tenantId, string clientId)
        {
            IdentityModelEventSource.ShowPII = true;
            ICollection<SecurityKey> keys = null;
            ConfigurationManager<OpenIdConnectConfiguration> configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever());
            try
            {
                // Try to get public key from Azure service.
                OpenIdConnectConfiguration config = configurationManager.GetConfigurationAsync().GetAwaiter().GetResult();
                keys = config.SigningKeys;
            }
            catch (Exception ex)
            {
                keys = null;
            }
            string cacheKey = CacheKeysConstraint.SigningKeys.Replace("[tenantId]", tenantId)
                .Replace("[clientId]", clientId);
            // Successed to get public key
            if (keys != null)
            {
                MemoryCacheEntryOptions cacheEntryOptions = new MemoryCacheEntryOptions();
                cacheEntryOptions.SetSlidingExpiration(TimeSpan.FromMinutes(5));
                cacheEntryOptions.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1);
                _memoryCache.Set(cacheKey, keys);
            }
            // Failed to get public key, then try to get cached public key.
            else
            {
                _memoryCache.TryGetValue(cacheKey, out keys);
            }

            return keys;
        }

        /// <summary>
        /// 验证JWT过期时间
        /// </summary>
        /// <param name="expirationTime">原始过期时间</param>
        /// <param name="extraValidityDay">延期有效时间</param>
        /// <returns></returns>
        public bool ValidateJWTExpirationTime(string expirationTime, int extraValidityDay)
        {
            var elapsedSeconds = 0d;
            if (!double.TryParse(expirationTime, out elapsedSeconds))
            {
                return false;
            }
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var extendExpirationTime = epoch.AddSeconds(elapsedSeconds).AddDays(extraValidityDay);
            if (extendExpirationTime > DateTime.UtcNow)
            {
                return true;
            }

            return false;
        }
    }
}
