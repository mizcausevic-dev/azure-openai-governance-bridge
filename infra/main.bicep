// main.bicep — provisions the governance bridge Function App in front of an
// existing Azure OpenAI resource. Deploy with:
//
//   az deployment group create -g <rg> -f infra/main.bicep \
//     -p aoaiEndpoint=https://my-aoai.openai.azure.com aoaiApiKey=<key>
//
// The Function App is configured with the bridge's app settings; ship the
// code with `func azure functionapp publish <appName>`.

@description('Base name; resources derive from it.')
param baseName string = 'kg-aoai-bridge'

@description('Location for all resources.')
param location string = resourceGroup().location

@description('Existing Azure OpenAI endpoint the bridge forwards to.')
param aoaiEndpoint string

@description('Azure OpenAI API key (store in Key Vault for production).')
@secure()
param aoaiApiKey string

@description('Optional audit-stream-py base URL or /events endpoint.')
param auditStreamUrl string = ''

@description('Audit stream bearer token. Required by the producer when auditStreamUrl is set.')
@secure()
param auditStreamToken string = ''

@description('JSON array of bridge rules[] bundles; separate from the signed Decision Card gate.')
param policyBundlesJson string = '[]'

@description('Signed Decision Card and attestation JSON envelope; load from an operator-controlled secret source.')
@secure()
param governanceDecisionCardJson string

@description('Independently pinned buyer ID for the signed Decision Card.')
param governanceBuyerId string

@description('Independently pinned HTTPS buyer key URL for the signed Decision Card.')
param governanceBuyerKeyUrl string

@description('Independently pinned base64 Ed25519 buyer public key.')
param governanceBuyerPublicKeyB64 string

@description('Operator-fixed vendor ID for this one workload.')
param governanceVendorId string

@description('Server-side identity for this single workload; give each workload its own Function app and key.')
param governanceCallerId string

@description('Server-side policy environment. Request headers cannot override this.')
@allowed(['production', 'staging', 'development'])
param governanceEnvironment string = 'production'

var storageName = toLower(replace('${baseName}sa', '-', ''))
var planName = '${baseName}-plan'
var functionName = '${baseName}-fn'
var insightsName = '${baseName}-ai'

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

resource insights 'Microsoft.Insights/components@2020-02-02' = {
  name: insightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
}

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: planName
  location: location
  sku: { name: 'Y1', tier: 'Dynamic' } // Consumption plan
  properties: { reserved: true } // Linux
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionName
  location: location
  kind: 'functionapp,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'Python|3.12'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      appSettings: [
        { name: 'AzureWebJobsStorage', value: 'DefaultEndpointsProtocol=https;AccountName=${storage.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storage.listKeys().keys[0].value}' }
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'python' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: insights.properties.ConnectionString }
        { name: 'AZURE_OPENAI_ENDPOINT', value: aoaiEndpoint }
        { name: 'AZURE_OPENAI_API_KEY', value: aoaiApiKey }
        { name: 'AZURE_OPENAI_API_VERSION', value: '2024-10-21' }
        { name: 'AUDIT_STREAM_URL', value: auditStreamUrl }
        { name: 'AUDIT_STREAM_TOKEN', value: auditStreamToken }
        { name: 'POLICY_BUNDLES_JSON', value: policyBundlesJson }
        { name: 'GOVERNANCE_DECISION_CARD_JSON', value: governanceDecisionCardJson }
        { name: 'GOVERNANCE_BUYER_ID', value: governanceBuyerId }
        { name: 'GOVERNANCE_BUYER_KEY_URL', value: governanceBuyerKeyUrl }
        { name: 'GOVERNANCE_BUYER_PUBLIC_KEY_B64', value: governanceBuyerPublicKeyB64 }
        { name: 'GOVERNANCE_VENDOR_ID', value: governanceVendorId }
        { name: 'DEFAULT_OUTCOME', value: 'deny' }
        { name: 'GOVERNANCE_CALLER_ID', value: governanceCallerId }
        { name: 'GOVERNANCE_ENVIRONMENT', value: governanceEnvironment }
      ]
    }
  }
}

output functionAppName string = functionApp.name
output functionAppHostname string = functionApp.properties.defaultHostName
