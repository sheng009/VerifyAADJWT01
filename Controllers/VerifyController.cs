using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using VerifyAADJWT01.Services;

namespace VerifyAADJWT01.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class VerifyController : ControllerBase
    {
        #region Members.
        private VerifyService _verifyService;
        private IMemoryCache _memoryCache;
        #endregion

        #region Construtors.
        public VerifyController(IMemoryCache memoryCache)
        {
            _memoryCache = memoryCache;
            _verifyService = new VerifyService("asdv234234^&%&^%&^hjsdfb2%%%", _memoryCache);
        }
        #endregion

        #region Methods.
        [HttpGet]
        public ContentResult Home()
        {
            return new ContentResult
            {
                StatusCode = 200,
                Content = "Please use https://verifyaadjwt0120200814124656.azurewebsites.net/api/verify/CheckAADJWT?tenantId=06aa9b7a-f7ae-4e01-9581-a769e9fc1bd6&clientId=a20ecdc7-18c5-4e42-81e7-c6153fa00e5c&token="
                    + "\r\n\r\n\r\n\r\nSample expired token:\r\n\r\neyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imh1Tjk1SXZQZmVocTM0R3pCRFoxR1hHaXJuTSIsImtpZCI6Imh1Tjk1SXZQZmVocTM0R3pCRFoxR1hHaXJuTSJ9.eyJhdWQiOiJhcGk6Ly9mYWEwYWZiOC1iZmU1LTQ2NDgtODJlOS1jNmYzYjkwOWZjZjQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8wNmFhOWI3YS1mN2FlLTRlMDEtOTU4MS1hNzY5ZTlmYzFiZDYvIiwiaWF0IjoxNTk3MzA1OTY2LCJuYmYiOjE1OTczMDU5NjYsImV4cCI6MTU5NzMwOTg2NiwiYWNyIjoiMSIsImFpbyI6IkFTUUEyLzhRQUFBQTM2SFlXK01EKzFlV1liZDcrRGtGMUR0L3ZEWS84NUdMWHF1SHZ3TVdVdjQ9IiwiYW1yIjpbInB3ZCJdLCJhcHBpZCI6ImEyMGVjZGM3LTE4YzUtNGU0Mi04MWU3LWM2MTUzZmEwMGU1YyIsImFwcGlkYWNyIjoiMSIsImZhbWlseV9uYW1lIjoi5rWm5bGxIiwiZ2l2ZW5fbmFtZSI6IuWkp-i8nSIsImlwYWRkciI6IjIxMC43NC4xNTYuMjUwIiwibmFtZSI6Im0tdXJheWFtYSIsIm9pZCI6ImQ5NmI3YTBjLTE5YzYtNDMwYi1iZjhmLTgyNTQ2NzhiZWMyMyIsInNjcCI6IlRva2VuLlZhbGlkYXRpb24iLCJzdWIiOiJoeERtM3lSUXZnTXFhVDk5eEt6eV9fYUxMT1ltTHJaaU1NSE5od2MxdDJVIiwidGlkIjoiMDZhYTliN2EtZjdhZS00ZTAxLTk1ODEtYTc2OWU5ZmMxYmQ2IiwidW5pcXVlX25hbWUiOiJtLXVyYXlhbWFAQUFEUmVzZWFyY2hGb3JVc2Vycy5vbm1pY3Jvc29mdC5jb20iLCJ1cG4iOiJtLXVyYXlhbWFAQUFEUmVzZWFyY2hGb3JVc2Vycy5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiJya3dOY1ZuVVkwUzVjQUtRSDJBZ0FBIiwidmVyIjoiMS4wIn0.WitCvRORbuyjnUtce2EtK5bUELAxYRWVLlHo3X1uW8Ele_qQ-2q7L49SFMSppqAUu8hi9wpoqtIg4msCiizyTWu6IqAQjkPq_dd9IkJ9jB7FVzi1b8KTnP8FInOtOZcnLRD3B-MQ6nLy7Azh3BaRvPXjPmWGWWXxWJjg5C51XAUhiYJzireS_yds1gbm2cmCruQCp_BcnBDhe3Is3EoxRKf_sFxJlqkr41HnHZml5lNjiX3JyvyokwmEhJy_Y3RvHH6O8K5Gpy_3t5LaG17EFsdW1MqI8JfqMdRMMKO7oxzLT5SErCVoa4NcheOIBOnI7iuzdYU6340_jmVxidMFIQ"
            };
        }

        [HttpGet]
        public JsonResult CheckAADJWT(string token, string tenantId, string clientId)
        {
            var stsDiscoveryEndpoint = $"https://login.microsoftonline.com/{tenantId}/v2.0/.well-known/openid-configuration";
            var signingKeys = _verifyService.GetSigningKeys(stsDiscoveryEndpoint, token, tenantId, clientId);
            if (signingKeys == null)
            {
                return new JsonResult(new { status = false, msg = $"Token validation failed. You can try it later." });
            }

            var isValidity = _verifyService.ValidateAADJWT(token, tenantId, stsDiscoveryEndpoint, signingKeys, false);
            if (isValidity)
            {
                // token is valid
                if (!_verifyService.ValidateJWTExpirationTime(_verifyService.GetClaim(token, "exp"), 0))
                {
                    // token is expired
                    return new JsonResult(new { status = false, msg = $"Token is expired." });
                }
                // token is valid and not expired
                return new JsonResult(new { status = true, msg = "Token is valid." });
            }

            return new JsonResult(new { status = false, msg = $"Token validation failed." });
        }
        #endregion
    }
}