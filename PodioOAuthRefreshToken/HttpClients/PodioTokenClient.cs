using System.Threading.Tasks;
using PodioAPI;
using PodioAPI.Utils.Authentication;

namespace PodioOAuthRefreshToken.HttpClients
{
    public class PodioTokenClient
    {
        public PodioTokenClient(string clientId, string clientSecret, string refreshToken)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _refreshToken = refreshToken;
        }

        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _refreshToken;

        public async Task<PodioOAuth> RefreshToken()
        {
            var podio = new Podio(_clientId, _clientSecret) {OAuth = new PodioOAuth {RefreshToken = _refreshToken}};
            return await podio.RefreshAccessToken();
        }
    }
}