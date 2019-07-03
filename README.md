# PodioOAuthRefreshToken
My implementation of AspNet Core 3rd-party Oauth. Podio is foreign service from which i need to get a token, and then a refresh token automatically. 

How it works:

1) Asp net core Authentication checks cookies. If cookies do not exist, the oauth flow will be started (redirect to AuthorizationEndpoint, 
redirect back, obtain ticket, creating cookie).
2) If cookies exist, the OnValidatePrincipal event will be started. It obtains "expires_at" property and checks it. If token expires, 
the refresh token process will be started (PodioTokenClient.RefreshToken), as a result of which we will get a new access token and calculate new expires.
