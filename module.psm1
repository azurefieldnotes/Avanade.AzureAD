#requires -Modules 'Microsoft.PowerShell.Utility' -Version 3.0
<#
    Functions for the Authorization against Azure Active Directory
    Copyright Chris Speers, Avanade 2016
    No warranty implied or expressed, side effects include insomnia, runny nose, vomiting
#>

$ErrorActionPreference='Stop'

#Winforms Sync Context
$Script:FormSyncContext=[hashtable]::Synchronized(@{})

$Script:DefaultAuthUrl='https://login.microsoftonline.com'
$Script:DefaultTokenApiVersion="2.1"
$Script:WSFedUserRealmApiVersion="1.0"

#region SAML Constants
$Script:Saml1AssertionType="urn:oasis:names:tc:SAML:1.0:assertion"
$Script:Saml2AssertionType="urn:oasis:names:tc:SAML:2.0:assertion"
$Script:SamlBearer11TokenType="urn:ietf:params:oauth:grant-type:saml1_1-bearer"
$Script:SamlBearer20TokenType = "urn:ietf:params:oauth:grant-type:saml2-bearer";
#TODO:OAuth OnBehalfOf
$Script:JwtBearerTokenType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
#endregion

$Script:DefaultNativeRedirectUri="urn:ietf:wg:oauth:2.0:oob"

#region STS Envelope
$Script:WSTrustSoapEnvelopeTemplate=@"
    <s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' 
                xmlns:a='http://www.w3.org/2005/08/addressing' 
                xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'>
        <s:Header>
        <a:Action s:mustUnderstand='1'>http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action>
        <a:messageID>urn:uuid:{2}</a:messageID>
        <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
        <a:To s:mustUnderstand='1'>{3}</a:To>
        <o:Security s:mustUnderstand='1' xmlns:o='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'>
            <u:Timestamp u:Id='_0'>
                <u:Created>{4}</u:Created>
                <u:Expires>{5}</u:Expires>
            </u:Timestamp>
            <o:UsernameToken u:Id='uuid-{2}'>
                <o:Username>{0}</o:Username>
                <o:Password>{1}</o:Password>
            </o:UsernameToken>
        </o:Security>
        </s:Header>
        <s:Body>
        <trust:RequestSecurityToken xmlns:trust='http://docs.oasis-open.org/ws-sx/ws-trust/200512'>
        <wsp:AppliesTo xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy'>
        <a:EndpointReference>
        <a:Address>urn:federation:MicrosoftOnline</a:Address>
        </a:EndpointReference>
        </wsp:AppliesTo>
        <trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType>
        <trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>
        </trust:RequestSecurityToken>
        </s:Body>
    </s:Envelope>
"@
#endregion

#region Helper methods

<#
    .SYNOPSIS
        Removes Base64 Padding from a string
    .PARAMETER Data
        The Input String
#>
Function RemoveBase64PaddingFromString
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $Data
    )

    $UnpaddedData=$Data.Replace('-', '+').Replace('_', '/')
    switch ($Data.Length % 4)
    {
        0 { break }
        2 { $UnpaddedData += '==' }
        3 { $UnpaddedData += '=' }
        default { throw New-Object ArgumentException('data') }
    }

    return $UnpaddedData
}

<#
    .SYNOPSIS
        Creates a new WinForm hosting a WebBrowser control to navigate to a URI
    .PARAMETER NavigateUri
        The Uri for the WebBrowser to navigate upon form load
    .PARAMETER FormTitle
        The default title on the form
    .PARAMETER FormWidth
        The form width
    .PARAMETER FormHeight
        The form height
#>
Function CreateWebForm
{
    [OutputType([System.Windows.Forms.Form])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $NavigateUri,
        [Parameter(Mandatory=$true)]
        [string]
        $FormTitle,
        [Parameter(Mandatory=$true)]
        [int]
        $FormWidth,
        [Parameter(Mandatory=$true)]
        [int]
        $FormHeight,
        [Parameter(Mandatory=$false)]
        [System.Windows.Forms.FormStartPosition]
        $StartupPosition=[System.Windows.Forms.FormStartPosition]::CenterParent
    )

    $Script:FormSyncContext=[hashtable]::Synchronized(@{})
    #New WinForm
    $FormSize = New-Object System.Drawing.Size($FormWidth,$FormHeight)
    $objForm = New-Object System.Windows.Forms.Form
    
    #Navigate on load
    $OnFormLoad={
        param
        (
            [Parameter()]
            [object]
            $sender,
            [Parameter()]
            [System.EventArgs]
            $e
        )
        Write-Verbose "Loaded! Navigating to $($Script:FormSyncContext.NavigateUri)"
        $Script:FormSyncContext.Browser.Navigate($Script:FormSyncContext.NavigateUri,$false)    
    }
    $objForm.add_Load($OnFormLoad)
 
    #Add a web browser control
    $webBrowser=New-Object System.Windows.Forms.WebBrowser
    $webBrowser.Location=(New-Object System.Drawing.Point(0,0))
    $webBrowser.MinimumSize=(New-Object System.Drawing.Size(20, 20))
    $webBrowser.Dock=[System.Windows.Forms.DockStyle]::Fill
    $webBrowser.Name="WebBrowser"

    #$objForm.StartPosition = "CenterScreen"
    $objForm.AutoScaleMode=[System.Windows.Forms.AutoScaleMode]::Font
    $objForm.AutoScaleDimensions=New-Object System.Drawing.SizeF(6.0,13.0)
    $objForm.ClientSize=$FormSize
    $objForm.Controls.Add($webBrowser)
    $objForm.Text = $FormTitle

    [System.Windows.Forms.Application]::EnableVisualStyles()

    #Put these on the sync context
    $Script:FormSyncContext.Form=$objForm
    $Script:FormSyncContext.Browser=$webBrowser
    $Script:FormSyncContext.NavigateUri=$NavigateUri.AbsoluteUri
    return $objForm
}

<#
    .SYNOPSIS
        Evaluates the WSFederation Metadata for the IntegratedAuth and UsernamePassword endpoints
    .PARAMETER MexDocument
        The WSFederation Metadata Document
#>
Function GetMexPolicies
{
    [CmdletBinding(ConfirmImpact='None')]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [System.Xml.XmlDocument]
        $MexDocument
    )
    
    $MexPolicies=@{}

    foreach ($policy in $MexDocument.definitions.Policy)
    {
        if($policy.ExactlyOne -eq $null)
        {
            continue
        }
        else
        {
            Write-Verbose "[GetMexPolicies] Examining Policy $($policy.Id)"
            $AllElement=$policy.ExactlyOne.All
            $NegElem=$AllElement.NegotiateAuthentication

            if($NegElem -ne $null)
            {
                Write-Verbose "[GetMexPolicies] IntegratedAuth policy $($policy.Id) Added."
                $MexPolicies.Add("#$($policy.Id)",(New-Object PSObject -Property @{Id=$policy.Id;AuthType=0}))
            }

            $SupTokenElem=$AllElement.SignedEncryptedSupportingTokens
            if($SupTokenElem -eq $null)
            {
                continue
            }

            $SupTokenPolicyElem=$SupTokenElem.Policy
            if($SupTokenPolicyElem -eq $null)
            {
                continue
            }

            $UserNameElem=$SupTokenPolicyElem.UsernameToken
            if($UserNameElem -eq $null -or $UserNameElem.Policy -eq $null -or $UserNameElem.Policy.WssUsernameToken10 -eq $null)
            {
                continue
            }         
            $MexPolicies.Add("#$($policy.Id)",(New-Object PSObject -Property @{Id=$policy.Id;AuthType=1}))
            Write-Verbose "[GetMexPolicies] Username/Password Policy $($policy.Id) Added."
        }
    }
    return $MexPolicies
}

<#
    .SYNOPSIS
        Retrieves the bindings from the WSFederation metadata
    .PARAMETER MexDocument
        The WSFederation Metadata Document
#>
Function GetMexBindings
{
    [CmdletBinding(ConfirmImpact='None')]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [System.Xml.XmlDocument]
        $MexDocument
    )

    $MexBindings=@{}
    
    $MexPolicies=GetMexPolicies -MexDocument $MexDocument
    Write-Verbose "[GetMexBindings] Found $($MexPolicies.Count) Policies"

    foreach ($item in $MexDocument.definitions.binding)
    {
        Write-Verbose "[GetMexBindings] Examining Binding $($item.name)"        
        $ItemName=$item.name
        if([String]::IsNullOrEmpty($ItemName))
        {
            continue
        }
        $PolicyRefNode=$item.PolicyReference
        
        if($PolicyRefNode -eq $null)
        {
            continue
        }
        $ItemUri=$PolicyRefNode.URI
        Write-Verbose "[GetMexBindings] Examining Policy Reference $ItemUri"
        if([String]::IsNullOrEmpty($ItemUri) -or $MexBindings.ContainsKey($ItemUri))
        {
            continue
        }
        
        $OperationNode=$item.operation
        if($OperationNode -eq $null)
        {
            continue
        }
        
        $OperationSubNode=$OperationNode.operation
        if($OperationSubNode -eq $null)
        {
            continue
        }
        
        if([String]::IsNullOrEmpty($OperationSubNode.soapAction))
        {
            continue
        }
        
        $BindingNode=$item.binding
        if($BindingNode -eq $null)
        {
            continue
        }
        
        if([String]::IsNullOrEmpty($BindingNode.transport))
        {
            continue
        }
        
        $MexPolicy=$MexPolicies[$ItemUri]
        if($MexPolicy -eq $null)
        {
            continue
        }
        
        $MexBindings.Add($ItemName,$MexPolicy)
        Write-Verbose "[GetMexBindings] Binding $ItemUri - $ItemName Added."
    }

    return $MexBindings
}

<#
    .SYNOPSIS
        Evaluates the response envelope for SAML assertion tokens
    .PARAMETER StsResponse
        The SOAP Envelope from the STS
#>
Function GetSecurityTokensFromEnvelope
{
    [OutputType([PSObject[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [System.Xml.XmlDocument]
        $StsResponse
    )
    $Tokens=@()
    $EnvelopeBody=$StsResponse.Envelope.Body
    $TokenResponseCollection=$EnvelopeBody.RequestSecurityTokenResponseCollection
    if($TokenResponseCollection -ne $null)
    {
        foreach ($TokenResponse in $TokenResponseCollection.RequestSecurityTokenResponse)
        {
            $TokenTypeId=$TokenResponse.TokenType
            $RequestedToken=$TokenResponse.RequestedSecurityToken
            $TokenAssertion=$RequestedToken.Assertion.OuterXml
            if($TokenTypeId -eq $Script:Saml1AssertionType)
            {
                $AssertionType=$Script:SamlBearer11TokenType
            }
            elseif($TokenTypeId -eq $Script:Saml2AssertionType)
            {
                $AssertionType=$Script:SamlBearer20TokenType
            }
            #We will default to 2.0 like
            else
            {
                $AssertionType=$Script:SamlBearer20TokenType
            }
            $Token=New-Object psobject -Property @{
                AssertionType=$AssertionType;
                TokenType=$TokenTypeId;
                Token=$TokenAssertion;
            }
            $Tokens+=$Token
        }
    }
    return $Tokens
}

<#
    .SYNOPSIS
        Issues a SOAP authentication request to the Security Token Service
    .PARAMETER AuthUri
        The authorization endpoint
    .PARAMETER UserName
        The user to be authenticated
    .PARAMETER Password
        The password for authentication
#>
Function GetStsResponse
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $AuthUri,
        [Parameter(Mandatory=$true)]
        [String]
        $UserName,
        [Parameter(Mandatory=$true)]
        [String]
        $Password,
        [Parameter(Mandatory=$false)]
        [Int32]
        $LengthInMinutes=10,
        [Parameter(Mandatory=$true)]
        [String]
        $SoapEnvelopeTemplate
    )

    $UUID=[Guid]::NewGuid()
    $StartTime=([DateTime]::UtcNow).ToString("yyyy'-'MM'-'ddTHH':'mm':'ss'Z'")
    $EndTime=([DateTime]::UtcNow).AddMinutes($LengthInMinutes).ToString("yyyy'-'MM'-'ddTHH':'mm':'ss'Z'")
    $AuthSoapEnvelope=($SoapEnvelopeTemplate -f $UserName,$Password,$UUID,$AuthUri.AbsoluteUri,$StartTime,$EndTime)
    $Headers=@{
        SOAPAction=$SoapAction;
    }
    $result=Invoke-RestMethod -Uri $AuthUri -Headers $Headers -Body $AuthSoapEnvelope -Method Post -ContentType "application/soap+xml" -ErrorAction Stop
    return $result
}

Function GetAzureADUserRealm
{
    [OutputType([System.Management.Automation.PSCustomObject])]
    [CmdletBinding(ConfirmImpact='None')]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [System.String]
        $UserPrincipalName,
        [Parameter(Mandatory=$false)]
        [System.Uri]
        $AuthorizationEndpoint=$Script:DefaultAuthUrl
    )
    $RealmUriBuilder=New-Object System.UriBuilder($AuthorizationEndpoint)
    $RealmUriBuilder.Path="/common/UserRealm"
    $RealmUriBuilder.Query="api-version=2.1&user=$UserPrincipalName"
    $RealmDetails=Invoke-RestMethod -Uri $RealmUriBuilder.Uri -ContentType "application/json" -ErrorAction Stop
    return $RealmDetails
}

Function GetWSFedBindings
{
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding(ConfirmImpact='None')]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Xml.XmlDocument]
        $MexDocument
    )

    $MexPolicyBindings=GetMexBindings -MexDocument $MexDocument
    Write-Verbose "[GetWSFedBindings] Found $($MexPolicyBindings.Count) binding(s)"
    foreach($port in $MexDocument.definitions.service.port)
    {
        $BindingName=$port.binding
        if([String]::IsNullOrEmpty($BindingName))
        {
            continue
        }
        $uri=$BindingName.Split(':',2)|Select-Object -Last 1
        Write-Debug "[GetWSFedBindings] Examining Port:$uri" 
        if($MexPolicyBindings[$uri] -eq $null)
        {
            continue
        }
        $EndpointNode=$port.EndpointReference
        if($EndpointNode -eq $null)
        {
            continue
        }
        $AddressNode=$EndpointNode.Address
        if($AddressNode -eq $null)
        {
            continue
        }
        Write-Verbose "[GetWSFedBindings] Adding Url:$AddressNode for item $uri"
        $EndpointUri=New-Object System.Uri($AddressNode)
        $MexPolicyBindings[$uri]|Add-Member -MemberType NoteProperty -Name Url -Value $EndpointUri
    }
    Write-Verbose "Found $($MexPolicyBindings.Count) binding(s)."
    return $MexPolicyBindings
}

<#
    .SYNOPSIS
        Evaluates a WSFed metadata document for the specified authentication type
    .PARAMETER MexDocument
        The WSFed metadata
    .PARAMETER AuthType
        The desired authentication type
#>
Function GetWSFedEndpoint
{
    [CmdletBinding(ConfirmImpact='None')]
    [OutputType([System.Uri])]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Xml.XmlDocument]
        $MexDocument,
        [Parameter(Mandatory=$true)]
        [ValidateSet("IntegratedAuth","UsernamePassword")]
        [System.String]
        $AuthType
    )
    $DesiredAuth=0
    if($AuthType -eq "IntegratedAuth")
    {
        $DesiredAuth=0
    }
    else
    {
        $DesiredAuth=1
    }

    $MexBindings=GetWSFedBindings -MexDocument $MexDocument
    Write-Verbose "[GetWSFedEndpoint] Examining Metadata Bindings..."
    foreach ($BindingId in $MexBindings.Keys)
    {
        Write-Debug "[GetWSFedEndpoint] Examining Binding $($BindingId)"
        $Binding=$MexBindings[$BindingId]
        if($Binding.AuthType -eq $DesiredAuth)
        {
            Write-Debug "[GetWSFedEndpoint] Endpoint:$Binding.Url is a match!"
            return $Binding.Url
        }
    }
}

<#
    .SYNOPSIS
        Issues a request to the security token service and evaluates SAML assertion tokens
    .PARAMETER AuthUri
        The security token service URI
    .PARAMETER Credential
        The credential to use for authentication
#>
Function GetWSTrustResponse
{
    [OutputType([PSObject])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $AuthUri,
        [Parameter(Mandatory=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$false)]
        [String]
        $SoapEnvelopeTemplate=$Script:WSTrustSoapEnvelopeTemplate,
        [Parameter(Mandatory=$false)]
        [System.String]
        $SoapAction=$Script:IssueSoapAction
    )
    
    $UserName=$Credential.UserName
    $Password=$Credential.GetNetworkCredential().Password
    Write-Verbose "[GetWSTrustResponse] Executing SOAP Action against $AuthUri"
    $result=GetStsResponse -AuthUri $AuthUri -UserName $UserName -Password $Password -SoapEnvelopeTemplate $SoapEnvelopeTemplate
    Write-Verbose "[GetWSTrustResponse] Evaluating Response Envelope"
    $StsTokens=GetSecurityTokensFromEnvelope -StsResponse $result
    $WSFedResponse=$StsTokens|Where-Object{$_.TokenType -eq $Script:Saml2AssertionType}
    if ($WSFedResponse -eq $null) {
        $WSFedResponse=$StsTokens|Where-Object{$_.TokenType -eq $Script:Saml1AssertionType}
    }
    if ($WSFedResponse -eq $null) {
        throw "Unable to create a User Assertion"
    }
    return $WSFedResponse
}

<#
    .SYNOPSIS
        Retrieves an OAuth User Assertion token from the specified username password endpoint
    .PARAMETER UsernamePasswordEndpoint
        The WSFed UsernamePassword endpoint
    .PARAMETER Credential
        The Credential to use for authentication
#>
Function GetWSTrustAssertionToken
{
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $UsernamePasswordEndpoint,
        [Parameter(Mandatory=$true)]
        [pscredential]
        $Credential
    )
    #TODO:See if we can do integrated auth....
    Write-Verbose "[GetWSTrustAssertionToken] Retrieving SAML Token from $UsernamePasswordEndpoint"
    $WsResult=GetWSTrustResponse -AuthUri $UsernamePasswordEndpoint -Credential $Credential
    Write-Verbose "[GetWSTrustAssertionToken] Retrieved SAML Token: $($WsResult.TokenType) Assertion $($WsResult.AssertionType)"
    #Encode the SAML assertion so we can get a token
    $AssertionType=$WsResult.AssertionType
    $TokenBytes=[System.Text.Encoding]::UTF8.GetBytes($WsResult.Token)
    $EncodedAssertion=[System.Convert]::ToBase64String($TokenBytes)
    #Go and get the token
    Write-Verbose "[GetWSTrustAssertionToken] Retrieving Bearer Token For User Assertion $($WsResult.AssertionType) for Resource:$Resource"
    $UriBuilder=New-Object System.UriBuilder($AuthorizationUri)
    $UriBuilder.Path="$TenantId/$TokenEndpoint"
    $UriBuilder.Query="api-version=$TokenApiVersion"
    $RequestBody=[ordered]@{
        'grant_type'=$AssertionType;
        'client_id'=$ClientId;
        'resource'=$Resource;
        'scope'='openid';
        'assertion'=$EncodedAssertion;
    }
    $Response=Invoke-RestMethod -Method Post -Uri $UriBuilder.Uri -Body $RequestBody -ErrorAction Stop
    return $Response
}

<#
    .SYNOPSIS
        Retreives an OAuth 2 JWT from Azure Active Directory as a fully managed User
    .PARAMETER Resource
        The Resource Uri to obtain a token for
    .PARAMETER ClientId
        The registered Azure Active Directory application id 
    .PARAMETER Credential
        The credential to use for authentication
    .PARAMETER TenantId
        The Azure Active Directory tenant id or domain name
    .PARAMETER AuthorizationUri
        The Azure Active Directory Token AuthorizationEndpoint
    .PARAMETER TokenEndpoint
        The Authorization Token Endpoint
    .PARAMETER TokenApiVersion
        The OAuth Token API Version           
#>
Function GetAzureADUserToken
{

    [CmdletBinding(ConfirmImpact='None')]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $Resource,
        [Parameter(Mandatory=$true)]
        [System.String]
        $ClientId,
        [Parameter(Mandatory=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true)]
        [System.String]
        $TenantId,
        [Parameter(Mandatory=$false)]
        [System.Uri]
        $AuthorizationUri=$Script:DefaultAuthUrl,
        [Parameter(Mandatory=$false)]
        [System.String]
        $TokenEndpoint='oauth2/token',
        [Parameter(Mandatory=$false)]
        [System.String]
        $TokenApiVersion=$Script:DefaultTokenApiVersion,
        [Parameter(Mandatory=$false)]
        [System.String]
        $TokenScope="openid"
    )

    $UserName=$Credential.UserName
    $Password=$Credential.GetNetworkCredential().Password

    $UriBuilder=New-Object System.UriBuilder($AuthorizationUri)
    $UriBuilder.Path="$TenantId/$TokenEndpoint"
    $UriBuilder.Query="api-version=$TokenApiVersion"
    Write-Verbose "[GetAzureADUserToken] Requesting User Token for User $UserName from $($UriBuilder.Uri.AbsoluteUri)"
    $Request=[ordered]@{
        'grant_type'='password';
        'resource'=$Resource;
        'client_id'=$ClientId;
        'username'=$UserName;
        'password'=$Password;
        'scope'=$TokenScope;
    }
    Write-Verbose "Acquiring Token From $($UriBuilder.Uri)"
    $Response=Invoke-RestMethod -Method Post -Uri $UriBuilder.Uri -Body $Request -ErrorAction Stop
    return $Response

}

<#
    .SYNOPSIS
        Retrieves an Authorization Code for an application interactively using the OAuth Consent Framework
    .PARAMETER AuthorizationUri
        The endpoint to navigate for an OAuth authorization code
        
#>
Function GetAzureADAuthorizationCode
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $AuthorizationUri
    )

    $ConsentForm=CreateWebForm -NavigateUri $AuthorizationUri -FormTitle "Sign in to Azure Active Directory" -FormWidth 500 -FormHeight 450
    $ConsentBrowser=$ConsentForm.Controls|Select-Object -First 1
    $OnBrowserNavigated={
        param
        (
            [Parameter()]
            [object]
            $sender,
            [Parameter()]
            [System.Windows.Forms.WebBrowserNavigatedEventArgs]
            $e
        )
        $TheForm=$sender.Parent
        Write-Verbose "Navigated $($e.Url)"
        $uri=New-Object System.Uri($e.Url)
        $QueryParams=$uri.Query.TrimStart('?').Split('&')
        #Make a hashtable of the query
        $Parameters=@{}
        foreach ($item in $QueryParams)
        {
            $pieces=$item.Split('=')
            $Parameters.Add($pieces[0],[System.Uri]::UnescapeDataString($pieces[1]))
        }
        #Look for the Authorization Code
        if($Parameters.ContainsKey('code'))
        {
            Write-Verbose "Authorization Code Received!"
            $Script:FormSyncContext.Code=$Parameters['code']
            $TheForm.DialogResult=[System.Windows.Forms.DialogResult]::OK
            $TheForm.Close()
        }
        #Look for an error (cancel)
        elseif($Parameters.ContainsKey('error'))
        {
            $TheForm.DialogResult=[System.Windows.Forms.DialogResult]::Abort
            $TheForm.Close()
            $Script:FormSyncContext.Error="$($Parameters['error']):$($Parameters['error_description'].Replace('+'," "))"
            Write-Verbose "Error Retrieving Access Code:$($Script:FormSyncContext.Error)"
        }
    }
    $OnDocumentCompleted={
        param
        (
            [object]$sender,
            [System.Windows.Forms.WebBrowserDocumentCompletedEventArgs]$e
        )
        $TheForm=$sender.Parent
        Write-Verbose "Document Completed! Size:$($sender.Document.Body.ScrollRectangle.Size)"
        $TheForm.Text= $sender.Document.Title
    }
    $ConsentBrowser.add_DocumentCompleted($OnDocumentCompleted)
    $ConsentBrowser.add_Navigated($OnBrowserNavigated)
    $ConsentResult=$ConsentForm.ShowDialog()
    if($ConsentResult -eq [System.Windows.Forms.DialogResult]::OK)
    {
        return $Script:FormSyncContext.Code
    }
    throw "The Operation Was Cancelled. $($Script:FormSyncContext.Error)"

}

<#
    .SYNOPSIS
        Retrieves an Access Token for an application interactively using the OAuth Consent Framework.
    .DESCRIPTION
        Retrieves an Access Token for an application interactively using the OAuth Consent Framework.
        Requires the application to allow Implicit Auth
    .PARAMETER AuthorizationUri
        The endpoint to navigate for an OAuth authorization token
        
#>
Function GetAzureADAccessToken
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $AuthorizationUri
    )

    $AuthForm=CreateWebForm -NavigateUri $AuthorizationUri -FormTitle "Sign in to Azure Active Directory" -FormWidth 500 -FormHeight 450
    $AuthBrowser=$AuthForm.Controls|Select-Object -First 1
    $OnBrowserNavigated={
        param
        (
            [Parameter()]
            [object]
            $sender,
            [Parameter()]
            [System.Windows.Forms.WebBrowserNavigatedEventArgs]
            $e
        )
        $TheForm=$sender.Parent
        Write-Verbose "Navigated $($e.Url)"
        $uri=New-Object System.Uri($e.Url)
        if($uri.AbsoluteUri.Contains("#") -and $uri.AbsoluteUri.Contains("access_token"))
        {
            $QueryVals=$uri.AbsoluteUri.Split('#')|Select-Object -Last 1
        }
        else 
        {
              $QueryVals=$uri.Query.TrimStart('?')
        }
        
        $QueryParams=$QueryVals.Split('&')
        #Make a hashtable of the query
        $Parameters=@{}
        foreach ($item in $QueryParams)
        {
            $pieces=$item.Split('=')
            $Parameters.Add($pieces[0],[System.Uri]::UnescapeDataString($pieces[1]))
        }
        #Look for the access token
        if($Parameters.ContainsKey('access_token'))
        {
            Write-Verbose "Access Token Received!"
            $AuthResult=New-Object PSObject -Property $Parameters
            $Script:FormSyncContext.AuthResult=$AuthResult
            $TheForm.DialogResult=[System.Windows.Forms.DialogResult]::OK
            $TheForm.Close()
        }
        #Look for an error (cancel)
        elseif($Parameters.ContainsKey('error'))
        {
            $TheForm.DialogResult=[System.Windows.Forms.DialogResult]::Abort
            $TheForm.Close()
            $Script:FormSyncContext.Error="$($Parameters['error']):$($Parameters['error_description'].Replace('+'," "))"
            Write-Verbose "Error Retrieving Access Code:$($Script:FormSyncContext.Error)"
        }
    }
    $OnDocumentCompleted={
        param
        (
            [object]$sender,
            [System.Windows.Forms.WebBrowserDocumentCompletedEventArgs]$e
        )
        $TheForm=$sender.Parent
        Write-Verbose "Document Completed! Size:$($sender.Document.Body.ScrollRectangle.Size)"
        $TheForm.Text= $sender.Document.Title
    }
    $AuthBrowser.add_DocumentCompleted($OnDocumentCompleted)
    $AuthBrowser.add_Navigated($OnBrowserNavigated)
    $AuthResult=$AuthForm.ShowDialog()
    if($AuthResult -eq [System.Windows.Forms.DialogResult]::OK)
    {
        return $Script:FormSyncContext.AuthResult
    }
    throw "The Operation Was Cancelled. $($Script:FormSyncContext.Error)"

}

#endregion

<#
    .SYNOPSIS
        Retrieves the WSFederation details for a given user prinicpal name
    .PARAMETER UserPrincipalName
        The user principal name(s) to retrieve details
    .PARAMETER AuthorizationEndpoint
        The OAuth WSFed Endpoint        
#>
Function Get-WSTrustUserRealmDetails
{
    [OutputType([pscustomobject])]
    [CmdletBinding(ConfirmImpact='None')]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.String]
        $UserPrincipalName,
        [Parameter(Mandatory=$false)]
        [System.Uri]
        $AuthorizationEndpoint=$Script:DefaultAuthUrl,
        [Parameter(Mandatory=$false)]
        [String]
        $UserRealmApiVersion=$Script:WSFedUserRealmApiVersion
    )

    $RealmUriBuilder=New-Object System.UriBuilder($AuthorizationEndpoint)
    $RealmUriBuilder.Path="/common/UserRealm/$UserPrincipalName"
    $RealmUriBuilder.Query="api-version=$UserRealmApiVersion"
    Write-Verbose "[Get-WSTrustUserRealmDetails] Retrieving User Realm Detail from $($RealmUriBuilder.Uri.AbsoluteUri) for $UserPrincipalName"
    $RealmDetails=Invoke-RestMethod -Uri $RealmUriBuilder.Uri -ContentType "application/json" -ErrorAction Stop
    return $RealmDetails
}

<#
    .SYNOPSIS
        Retrieves a set of objects representing User Realm details for a given User Principal NameSpaceType
    .PARAMETER UserPrincipalName
        The user principal name(s) to retrieve details
    .PARAMETER AuthorizationEndpoint
        The OAuth Endpoint
    .PARAMETER FederationEndpoint
        The WSFed Endpoint
    .DESCRIPTION
        Returns object(s) containing user realm details
        Managed Domains:
            RealmDetails
        Federated Domains:
            FederationDoc
            UsernamePasswordEndpoint
            Bindings
            RealmDetails
            WSFedRealmDetails
            AuthorizationUrl
            IntegratedAuthEndpoint

#>
Function Get-AzureADUserRealm
{
    [OutputType([System.Management.Automation.PSCustomObject[]])]
    [CmdletBinding(ConfirmImpact='None')]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [System.String[]]
        $UserPrincipalName,
        [Parameter(Mandatory=$false)]
        [System.Uri]
        $AuthorizationEndpoint=$Script:DefaultAuthUrl,
        [Parameter(Mandatory=$false)]
        [String]
        $UserRealmApiVersion=$Script:WSFedUserRealmApiVersion
    )

    BEGIN
    {
        $AllRealmDetails=@()
    }

    PROCESS
    {
        foreach ($UPN in $UserPrincipalName)
        {

            $RealmDetails=GetAzureADUserRealm -UserPrincipalName $UPN -AuthorizationEndpoint $AuthorizationEndpoint
            Write-Verbose "[Get-AzureADUserRealm] Realm Details $($RealmDetails.DomainName) $($RealmDetails.NamespaceType)"
            if($RealmDetails.NamespaceType -eq "Federated")
            {
                Write-Verbose "[Get-AzureADUserRealm] User is Federated"
                $WsFedRealmDetails=Get-WSTrustUserRealmDetails -UserPrincipalName $UPN -AuthorizationEndpoint $AuthorizationEndpoint
                $MexDataUrl=$WsFedRealmDetails.federation_metadata_url

                Write-Verbose "[Get-AzureADUserRealm] Retrieving Federation Metadata from $MexDataUrl"
                $FedDOc=Invoke-RestMethod -Uri $MexDataUrl -ContentType 'application/soap+xml'
                $WsTrustBindings=GetWSFedBindings -MexDocument $FedDoc
                $IntegratedEndpoint=GetWSFedEndpoint -MexDocument $FedDoc -AuthType IntegratedAuth -ErrorAction SilentlyContinue
                $UsernameEndpoint=GetWSFedEndpoint -MexDocument $FedDoc -AuthType UsernamePassword -ErrorAction SilentlyContinue
                $UserRealm=New-Object PSObject -Property @{
                    RealmDetails=$RealmDetails;
                    WSFedRealmDetails=$WsFedRealmDetails;
                    FederationDoc=$FedDoc;
                    Bindings=$WsTrustBindings;
                    IntegratedAuthEndpoint=$IntegratedEndpoint;
                    UsernamePasswordEndpoint=$UsernameEndpoint;
                    AuthorizationUrl=$RealmDetails.AuthUrl;
                }
            }
            else 
            {
                Write-Verbose "[Get-AzureADUserRealm] User is Managed"
                $UserRealm=New-Object PSObject -Property @{
                    RealmDetails=$RealmDetails;
                }    
            }
            $AllRealmDetails+=$UserRealm
        }
    }

    END
    {
        return $AllRealmDetails
    }

}

<#
    .SYNOPSIS
        Retreives an OAuth 2 JWT from Azure Active Directory as an Application
    .PARAMETER Resource
        The Resource Uri to obtain a token for
    .PARAMETER ClientId
        The registered Azure Active Directory application id 
    .PARAMETER ClientSecret
        The client secret to use for authentication
    .PARAMETER TenantId
        The Azure Active Directory tenant id or domain name
    .PARAMETER AuthorizationUri
        The Azure Active Directory Token AuthorizationEndpoint
    .PARAMETER TokenEndpoint
        The Authorization Token Endpoint
    .PARAMETER AuthCodeEndpoint
        The Authorization Code Endpoint
    .PARAMETER TokenApiVersion
        The OAuth Token API Version
#>
Function Get-AzureADClientToken
{
    [CmdletBinding(ConfirmImpact='None')]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $Resource,
        [Parameter(Mandatory=$true)]
        [System.String]
        $ClientId,
        [Parameter(Mandatory=$true)]
        [System.String]
        $ClientSecret,
        [Parameter(Mandatory=$false)]
        [System.String]
        $TenantId="common",
        [Parameter(Mandatory=$false)]
        [System.Uri]
        $AuthorizationUri=$Script:DefaultAuthUrl,
        [Parameter(Mandatory=$false)]
        [System.String]
        $TokenEndpoint='oauth2/token',
        [Parameter(Mandatory=$false)]
        [System.String]
        $TokenApiVersion=$Script:DefaultTokenApiVersion
    )

    $UriBuilder=New-Object System.UriBuilder($AuthorizationUri)
    $UriBuilder.Path="$TenantId/$TokenEndpoint"
    $UriBuilder.Query="api-version=$TokenApiVersion"
    Write-Verbose "[Get-AzureADClientToken] Retrieving token for Client:$ClientId Tenant:$TenantId with Client Secret:[REDACTED] at $($UriBuilder.Uri.AbsolutePath)"
    $Request=[ordered]@{
        'grant_type'='client_credentials';
        'client_id'=$ClientId;
        'client_secret'=$ClientSecret;
        'resource'=$Resource
    }
    $Response=Invoke-RestMethod -Method Post -Uri $UriBuilder.Uri -Body $Request -ErrorAction Stop
    Write-Verbose "[Get-AzureADClientToken] Success!"
    return $Response
}

<#
    .SYNOPSIS
        Retreives an OAuth 2 JWT from Azure Active Directory as a User
    .PARAMETER Resource
        The Resource Uri to obtain a token for
    .PARAMETER ClientId
        The registered Azure Active Directory application id 
    .PARAMETER Credential
        The credential to use for authentication
    .PARAMETER TenantId
        The Azure Active Directory tenant id or domain name
    .PARAMETER AuthorizationUri
        The Azure Active Directory Token AuthorizationEndpoint   
    .PARAMETER TokenEndpoint
        The Authorization Token Endpoint
    .PARAMETER AuthCodeEndpoint
        The Authorization Code Endpoint
    .PARAMETER TokenApiVersion
        The OAuth Token API Version
#>
Function Get-AzureADUserToken
{
    [OutputType([psobject])]
    [CmdletBinding(ConfirmImpact='None')]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $Resource,
        [Parameter(Mandatory=$true)]
        [System.String]
        $ClientId,
        [Parameter(Mandatory=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$false)]
        [System.String]
        $TenantId="common",
        [Parameter(Mandatory=$false)]
        [System.Uri]
        $AuthorizationUri=$Script:DefaultAuthUrl,
        [Parameter(Mandatory=$false)]
        [System.String]
        $TokenEndpoint='oauth2/token',
        [Parameter(Mandatory=$false)]
        [System.String]
        $AuthCodeEndpoint='oauth2/authorize',
        [Parameter(Mandatory=$false)]
        [System.String]
        $TokenApiVersion=$Script:DefaultTokenApiVersion    
    )
    Write-Verbose "[Get-AzureADUserToken] Retrieving OAuth Token for Client:$ClientId as $($Credential.UserName)"
    $UserRealm=Get-AzureADUserRealm -UserPrincipalName $Credential.UserName -AuthorizationEndpoint $AuthorizationUri
    Write-Verbose "[Get-AzureADUserToken] Realm $($UserRealm.RealmDetails.DomainName) NamespaceType:$($UserRealm.RealmDetails.NameSpaceType)"
    if($UserRealm.FederationDoc -eq $null)
    {
        Write-Verbose "[Get-AzureADUserToken] Retrieving OAuth Token for Client:$ClientId as $($Credential.UserName)"
        $UserResult=GetAzureADUserToken -Resource $Resource -ClientId $ClientId -Credential $Credential -TenantId $TenantId
        Write-Verbose "[Get-AzureADUserToken] Successfully received an OAuth Token!"
        return $UserResult
    }
    Write-Verbose "[Get-AzureADUserToken] Retrieving WSFed User Assertion Token"
    #Where to we need to authenticate???
    #TODO:See if we can do integrated auth....
    $AssertionResult=GetWSTrustAssertionToken -UsernamePasswordEndpoint $UserRealm.UsernamePasswordEndpoint -Credential $Credential
    Write-Verbose "[Get-AzureADUserToken] Successfully received a WSFed User Assertion Token!"
    return $AssertionResult
}

<#
    .SYNOPSIS
        Approve an Azure Active Directory Application using the OAuth consent framework
    .PARAMETER ClientId
        The registered Azure Active Directory application id
    .PARAMETER AuthorizationCode
        The Authorization Code to exchange
    .PARAMETER AuthorizationUri
        The Azure Active Directory Token AuthorizationEndpoint
    .PARAMETER TenantId
        The Azure Active Directory tenant id or domain name
    .PARAMETER RedirectUri
        The approved Redirect URI request for the application
    .PARAMETER TokenEndpoint
        The Authorization Token Endpoint
    .PARAMETER TokenApiVersion
        The OAuth Token API Version
    .PARAMETER AdminConsent
        Whether to grant admin consent during the request        
#>
Function Approve-AzureADApplication
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $ClientId,
        [Parameter(Mandatory=$false)]
        [System.Uri]
        $RedirectUri=$Script:DefaultNativeRedirectUri,
        [Parameter(Mandatory=$false)]
        [System.String]
        $TenantId="common",
        [Parameter(Mandatory=$false)]
        [System.Uri]
        $AuthorizationUri=$Script:DefaultAuthUrl,
        [System.String]
        $TokenEndpoint='oauth2/token',
        [Parameter(Mandatory=$false)]
        [System.String]
        $AuthCodeEndpoint='oauth2/authorize',
        [Parameter(Mandatory=$false)]
        [System.String]
        $TokenApiVersion=$Script:DefaultTokenApiVersion,
        [Parameter()]
        [Switch]
        $AdminConsent   
    )
    $ConsentUriBuilder=New-Object System.UriBuilder($AuthorizationUri)
    $ConsentUriBuilder.Path="$TenantId/$AuthCodeEndpoint"
    $ConsentType="consent"
    if($AdminConsent.IsPresent)
    {
        $ConsentType="admin_consent"
    }
    $ConsentUriBuilder.Query="api-version=$TokenApiVersion&client_id=$($ClientId)"
    $ConsentUriBuilder.Query+="&redirect_uri=$([Uri]::EscapeDataString($RedirectUri.AbsoluteUri))"
    $ConsentUriBuilder.Query+="&response_type=code&prompt=$ConsentType"
    $AuthCode=GetAzureADAuthorizationCode -AuthorizationUri $ConsentUriBuilder.Uri.AbsoluteUri
    return $AuthCode
}

<#
    .SYNOPSIS
        Exchanges an Azure Active Directory Authorization Code for a Token
    .PARAMETER Resource
        The Resource Uri to obtain a token for
    .PARAMETER ClientId
        The registered Azure Active Directory application id
    .PARAMETER TenantId
        The Azure Active Directory tenant id or domain name
    .PARAMETER AuthorizationCode
        The Authorization Code to exchange
    .PARAMETER AuthorizationUri
        The Azure Active Directory Token AuthorizationEndpoint
    .PARAMETER RedirectUri
        The approved Redirect URI request for the application
    .PARAMETER TokenEndpoint
        The Authorization Token Endpoint
    .PARAMETER TokenApiVersion
        The OAuth Token API Version
#>
Function Get-AzureADAccessTokenFromCode
{
    [OutputType([pscustomobject])]
    [CmdletBinding(ConfirmImpact='None')]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $Resource,
        [Parameter(Mandatory=$false)]
        [System.Uri]
        $RedirectUri=$Script:DefaultNativeRedirectUri,
        [Parameter(Mandatory=$true)]
        [System.String]
        $ClientId,
        [Parameter(Mandatory=$true)]
        [System.String]
        $AuthorizationCode,
        [Parameter(Mandatory=$false)]
        [System.String]
        $TenantId="common",
        [Parameter(Mandatory=$false)]
        [System.Uri]
        $AuthorizationUri=$Script:DefaultAuthUrl,
        [Parameter(Mandatory=$false)]
        [System.String]
        $TokenEndpoint='oauth2/token',
        [Parameter(Mandatory=$false)]
        [System.String]
        $TokenApiVersion=$Script:DefaultTokenApiVersion
    )

    $TokenUriBuilder=New-Object System.UriBuilder($AuthorizationUri)
    $TokenUriBuilder.Path="$TenantId/$TokenEndpoint"
    $TokenUriBuilder.Query="api-version=$TokenApiVersion"
    $Request=[ordered]@{
        'grant_type'='authorization_code';
        'client_id'=$ClientId;
        'resource'=$Resource;
        'scope'='openid';
        'code'=$AuthorizationCode;
        'redirect_uri'=$RedirectUri.AbsoluteUri;
    }
    $Response=Invoke-RestMethod -Method Post -Uri $TokenUriBuilder.Uri -Body $Request -ErrorAction Stop
    return $Response
}

<#
    .SYNOPSIS
        Retreives the Well known OpenId Connect conifguration for the tenant
    .PARAMETER TenantId
        The tenant to retrieve the details for
    .PARAMETER AuthorizationUri
        The target endpoint
#>
Function Get-AzureADOpenIdConfiguration
{
    [OutputType([pscustomobject])]
    [CmdletBinding(ConfirmImpact='None')]
    param
    (
        [Parameter(Mandatory=$false)]
        [String]
        $TenantId='common',
        [Parameter(Mandatory=$false)]
        [System.Uri]
        $AuthorizationUri=$Script:DefaultAuthUrl 
    )

    $OpenIdUriBuilder=New-Object System.UriBuilder($AuthorizationUri)
    $OpenIdUriBuilder.Path="$TenantId/.well-known/openid-configuration"
    $OpenIdConfig=Invoke-RestMethod -Uri $OpenIdUriBuilder.Uri -ContentType "application/json" -ErrorAction Stop
    return $OpenIdConfig
}

<#
    .SYNOPSIS
        Retrieves an OAuth access token interactively for an application allowing Implicit Flow
    .PARAMETER Resource
        The Resource Uri to obtain a token for
    .PARAMETER ClientId
        The registered Azure Active Directory application id
    .PARAMETER AuthorizationUri
        The Azure Active Directory Token AuthorizationEndpoint
    .PARAMETER TenantId
        The Azure Active Directory tenant id or domain name
    .PARAMETER RedirectUri
        The approved Redirect URI request for the application
    .PARAMETER AuthEndpoint
        The OAuth2 authorization endpoint
    .PARAMETER TokenApiVersion
        The OAuth Token API Version
    .PARAMETER Consent
        Whether to grant consent during the request
    .PARAMETER AdminConsent
        Whether to grant admin consent during the request
#>
Function Get-AzureADImplicitFlowToken
{
    [CmdletBinding(ConfirmImpact='None')]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $Resource,
        [Parameter(Mandatory=$true)]
        [System.String]
        $ClientId,
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $RedirectUri,
        [Parameter(Mandatory=$false)]
        [System.String]
        $TenantId="common",
        [Parameter(Mandatory=$false)]
        [System.Uri]
        $AuthorizationUri=$Script:DefaultAuthUrl,
        [Parameter(Mandatory=$false)]
        [System.String]
        $AuthEndpoint='oauth2/authorize',
        [Parameter(Mandatory=$false)]
        [System.String]
        $TokenApiVersion=$Script:DefaultTokenApiVersion,
        [Parameter()]
        [Switch]
        $Consent,
        [Parameter()]
        [Switch]
        $AdminConsent
    )

    $TokenUriBuilder=New-Object System.UriBuilder($AuthorizationUri)
    $TokenUriBuilder.Path="$TenantId/$AuthEndpoint"
    $TokenQuery="&redirect_uri=$([Uri]::EscapeDataString($RedirectUri.AbsoluteUri))&resource=$([Uri]::EscapeDataString($Resource.AbsoluteUri))"
    $TokenQuery+="&api-version=$TokenApiVersion&client_id=$($ClientId)&response_type=token"
    if($Consent.IsPresent)
    {
        $TokenQuery+="&prompt=consent"
    }
    elseif($AdminConsent.IsPresent)
    {
        $TokenQuery+="&prompt=admin_consent"
    }
    else
    {
        $TokenQuery+="&prompt=login"
    }
    $TokenUriBuilder.Query=$TokenQuery
    $AuthResult=GetAzureADAccessToken -AuthorizationUri $TokenUriBuilder.Uri
    return $AuthResult
}

<#
    .SYNOPSIS
        Converts an encoded JSON Web Token to an object representation
    .PARAMETER RawToken
        The encoded JWT string
    .PARAMETER AsString
        Returns the decoded JWT as a string delimiting sections with a period 
#>
Function ConvertFrom-EncodedJWT
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $RawToken,
        [Parameter()]
        [Switch]
        $AsString
    )
    Write-Debug "[ConvertFrom-EncodedJWT] Raw Token $RawToken"
    $TokenSections=$RawToken.Split(".");

    $EncodedHeaders=RemoveBase64PaddingFromString -Data $TokenSections[0]
    $EncodedHeaderBytes=[System.Convert]::FromBase64String($EncodedHeaders)
    $DecodedHeaders=[System.Text.Encoding]::UTF8.GetString($EncodedHeaderBytes)
    
    $EncodedPayload=RemoveBase64PaddingFromString -Data $TokenSections[1]
    $EncodedPayloadBytes=[System.Convert]::FromBase64String($EncodedPayload)
    $DecodedPayload=[System.Text.Encoding]::UTF8.GetString($EncodedPayloadBytes)
    
    $EncodedSignature=RemoveBase64PaddingFromString -Data $TokenSections[1]
    $EncodedSignatureBytes=[System.Convert]::FromBase64String($EncodedSignature)
    $DecodedSignature=[System.Text.Encoding]::UTF8.GetString($EncodedSignatureBytes)
    
    $JwtProperties=@{
        'headers'   = ($DecodedHeaders|ConvertFrom-Json);
        'payload'    = ($DecodedPayload|ConvertFrom-Json);
        'signature' = ($DecodedSignature|ConvertFrom-Json);
    }
    $DecodedJwt=New-Object PSObject -Property $JwtProperties
    if($AsString.IsPresent)
    {
        $OutputJwt="$DecodedHeaders`n.$DecodedPayload`n.$DecodedSignature"
        return $OutputJwt
    }
    else
    {
        return $DecodedJwt
    }
}