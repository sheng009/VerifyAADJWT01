using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace VerifyAADJWT01.Constraint
{
    public static class CacheKeysConstraint
    {
        public static string SigningKeys = "_SigningKeys_[tenantId]_[clientId]";
    }
}
