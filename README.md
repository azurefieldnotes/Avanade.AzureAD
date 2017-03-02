[Azure Field Notes Blog]: https://www.azurefieldnotes.com/2016/08/03/azure-azure-active-directory-powershell-hard-way/
[@azurefieldnotes]: https://twitter.com/azurefieldnotes
![OAuth Posh AAD](https://azurefieldnotesblog.blob.core.windows.net/wp-content/2016/08/poshoauth-300x196.png)
# Avanade.AzureAD PowerShell Module
## A PowerShell Module for obtaining tokens and authorizing applications in Azure Active Directory.

For all intents and purposes this is a swath of ADAL.NET functionality reimplemented in PowerShell

### Exposed Cmdlets
* Approve-AzureADApplication
    * Approves an Azure AD Application Interactively and returns the Authorization Code
* ConvertFrom-EncodedJWT
    * Converts an encoded JWT to an object representation
* Get-AzureADAccessTokenFromCode
    * Retrieves an access token from a consent authorization code
* Get-AzureADClientToken
    * Retrieves an access token as a an OAuth confidential client
* Get-AzureADImplicitFlowToken
    * Retrieves an access token interactively for a web application with OAuth implicit flow enabled
* Get-AzureADOpenIdConfiguration
    * Retrieves the OpenId connect configuration for the specified application
* Get-AzureADUserRealm
    * Retrieves a the aggregate user realm data for the specified user principal name(s)
* Get-AzureADUserToken
    * Retrieves an access token as a an OAuth public client
* Get-AzureADClientAssertionToken
    * Retrieves an OAuth access token using a certificate
* Get-WSTrustUserRealmDetails
    * Retrieves the WSFederation details for a given user prinicpal name
* Get-AzureADRefreshToken
    * Retrieves an OAuth2 JWT using the refresh token framework
* Test-JWTHasExpired
    * Test whether the current token has expired
* Get-JWTExpiry
    * Return the current JWT expiry as a DateTime
* Get-AzureADDiscoveryKey
    * Returns the set of openid discovery certficate details
* ConvertFrom-AzureADDiscoveryKey
    * Converts an openid discovery key to a certificate
## Read More at [Azure Field Notes Blog][] or follow us on Twitter at [@azurefieldnotes][]
