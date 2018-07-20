using System;
using System.Threading.Tasks;

namespace CoreServices
{
    public class AccountService
    {
        public async Task<object> BuildLoginViewModelAsync(object a)
        {
            return await Task.Run(() => { return a; });
        }
    }
}
