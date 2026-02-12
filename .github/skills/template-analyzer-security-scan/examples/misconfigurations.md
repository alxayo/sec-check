# Azure Template Misconfiguration Examples

This document provides examples of common security misconfigurations in ARM and Bicep templates that Template Analyzer detects.

> **Purpose**: Educational reference for understanding what Template Analyzer scans for and how to remediate findings.

## Transport Security Issues

### TA-000004/010/016: HTTPS Not Enforced

**Vulnerable ARM Template:**
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Web/sites",
      "apiVersion": "2022-03-01",
      "name": "myWebApp",
      "location": "[resourceGroup().location]",
      "properties": {
        "httpsOnly": false
      }
    }
  ]
}
```

**Secure ARM Template:**
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Web/sites",
      "apiVersion": "2022-03-01",
      "name": "myWebApp",
      "location": "[resourceGroup().location]",
      "properties": {
        "httpsOnly": true
      }
    }
  ]
}
```

**Vulnerable Bicep:**
```bicep
resource webApp 'Microsoft.Web/sites@2022-03-01' = {
  name: 'myWebApp'
  location: resourceGroup().location
  properties: {
    httpsOnly: false  // INSECURE
  }
}
```

**Secure Bicep:**
```bicep
resource webApp 'Microsoft.Web/sites@2022-03-01' = {
  name: 'myWebApp'
  location: resourceGroup().location
  properties: {
    httpsOnly: true  // SECURE
  }
}
```

---

### TA-000005/011/017: Outdated TLS Version

**Vulnerable:**
```json
{
  "type": "Microsoft.Web/sites/config",
  "apiVersion": "2022-03-01",
  "name": "myWebApp/web",
  "properties": {
    "minTlsVersion": "1.0"
  }
}
```

**Secure:**
```json
{
  "type": "Microsoft.Web/sites/config",
  "apiVersion": "2022-03-01",
  "name": "myWebApp/web",
  "properties": {
    "minTlsVersion": "1.2"
  }
}
```

**Secure Bicep:**
```bicep
resource webConfig 'Microsoft.Web/sites/config@2022-03-01' = {
  name: 'myWebApp/web'
  properties: {
    minTlsVersion: '1.2'  // Always use TLS 1.2 or higher
  }
}
```

---

### TA-000003/009/015: FTPS Not Enforced

**Vulnerable:**
```json
{
  "type": "Microsoft.Web/sites/config",
  "name": "myApp/web",
  "properties": {
    "ftpsState": "AllAllowed"
  }
}
```

**Secure:**
```json
{
  "type": "Microsoft.Web/sites/config",
  "name": "myApp/web",
  "properties": {
    "ftpsState": "FtpsOnly"
  }
}
```

Or disable FTP entirely:
```json
{
  "properties": {
    "ftpsState": "Disabled"
  }
}
```

---

## Authentication & Identity Issues

### TA-000007/013/019: No Managed Identity

**Vulnerable - No identity configured:**
```json
{
  "type": "Microsoft.Web/sites",
  "name": "myFunctionApp",
  "properties": {
    "siteConfig": {}
  }
}
```

**Secure - System-assigned managed identity:**
```json
{
  "type": "Microsoft.Web/sites",
  "name": "myFunctionApp",
  "identity": {
    "type": "SystemAssigned"
  },
  "properties": {
    "siteConfig": {}
  }
}
```

**Secure Bicep:**
```bicep
resource functionApp 'Microsoft.Web/sites@2022-03-01' = {
  name: 'myFunctionApp'
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'  // Or 'UserAssigned' or 'SystemAssigned, UserAssigned'
  }
  properties: {}
}
```

---

### TA-000026: Service Fabric Without AAD

**Vulnerable:**
```json
{
  "type": "Microsoft.ServiceFabric/clusters",
  "name": "myCluster",
  "properties": {
    "azureActiveDirectory": {}
  }
}
```

**Secure:**
```json
{
  "type": "Microsoft.ServiceFabric/clusters",
  "name": "myCluster",
  "properties": {
    "azureActiveDirectory": {
      "tenantId": "[parameters('aadTenantId')]",
      "clusterApplication": "[parameters('aadClusterApplicationId')]",
      "clientApplication": "[parameters('aadClientApplicationId')]"
    }
  }
}
```

---

## Encryption Issues

### TA-000021: Automation Account Variables Not Encrypted

**Vulnerable:**
```json
{
  "type": "Microsoft.Automation/automationAccounts/variables",
  "name": "myAutomationAccount/dbPassword",
  "properties": {
    "value": "sensitive-password-here",
    "isEncrypted": false
  }
}
```

**Secure:**
```json
{
  "type": "Microsoft.Automation/automationAccounts/variables",
  "name": "myAutomationAccount/dbPassword",
  "properties": {
    "value": "[parameters('dbPassword')]",
    "isEncrypted": true
  }
}
```

---

### TA-000022: Redis Cache Allows Non-SSL

**Vulnerable:**
```json
{
  "type": "Microsoft.Cache/Redis",
  "name": "myRedisCache",
  "properties": {
    "enableNonSslPort": true
  }
}
```

**Secure:**
```json
{
  "type": "Microsoft.Cache/Redis",
  "name": "myRedisCache",
  "properties": {
    "enableNonSslPort": false,
    "minimumTlsVersion": "1.2"
  }
}
```

---

### TA-000027: SQL Database Without TDE

**Vulnerable - No Transparent Data Encryption:**
```json
{
  "type": "Microsoft.Sql/servers/databases",
  "name": "myServer/myDatabase",
  "properties": {}
}
```

**Secure - TDE Enabled:**
```json
{
  "type": "Microsoft.Sql/servers/databases/transparentDataEncryption",
  "name": "myServer/myDatabase/current",
  "properties": {
    "state": "Enabled"
  }
}
```

---

## Access Control Issues

### TA-000006/012/018: CORS Allows All Origins

**Vulnerable:**
```json
{
  "type": "Microsoft.Web/sites/config",
  "name": "myApp/web",
  "properties": {
    "cors": {
      "allowedOrigins": ["*"]
    }
  }
}
```

**Secure:**
```json
{
  "type": "Microsoft.Web/sites/config",
  "name": "myApp/web",
  "properties": {
    "cors": {
      "allowedOrigins": [
        "https://myapp.contoso.com",
        "https://admin.contoso.com"
      ]
    }
  }
}
```

---

### TA-000023: Kubernetes Without Authorized IP Ranges

**Vulnerable:**
```json
{
  "type": "Microsoft.ContainerService/managedClusters",
  "name": "myAKSCluster",
  "properties": {
    "apiServerAccessProfile": {}
  }
}
```

**Secure - Authorized IP Ranges:**
```json
{
  "type": "Microsoft.ContainerService/managedClusters",
  "name": "myAKSCluster",
  "properties": {
    "apiServerAccessProfile": {
      "authorizedIPRanges": [
        "203.0.113.0/24",
        "198.51.100.0/24"
      ]
    }
  }
}
```

**Secure - Private Cluster:**
```json
{
  "type": "Microsoft.ContainerService/managedClusters",
  "name": "myAKSCluster",
  "properties": {
    "apiServerAccessProfile": {
      "enablePrivateCluster": true
    }
  }
}
```

---

### TA-000024: Kubernetes Without RBAC

**Vulnerable:**
```json
{
  "type": "Microsoft.ContainerService/managedClusters",
  "name": "myAKSCluster",
  "properties": {
    "enableRBAC": false
  }
}
```

**Secure:**
```json
{
  "type": "Microsoft.ContainerService/managedClusters",
  "name": "myAKSCluster",
  "properties": {
    "enableRBAC": true,
    "aadProfile": {
      "managed": true,
      "enableAzureRBAC": true
    }
  }
}
```

---

## API Management Issues

### TA-000029: APIs Not Using HTTPS Only

**Vulnerable:**
```json
{
  "type": "Microsoft.ApiManagement/service/apis",
  "name": "myAPIM/myAPI",
  "properties": {
    "protocols": ["http", "https"]
  }
}
```

**Secure:**
```json
{
  "type": "Microsoft.ApiManagement/service/apis",
  "name": "myAPIM/myAPI",
  "properties": {
    "protocols": ["https"]
  }
}
```

---

### TA-000035: Secrets Not in Key Vault

**Vulnerable - Inline secrets:**
```json
{
  "type": "Microsoft.ApiManagement/service/namedValues",
  "name": "myAPIM/dbConnectionString",
  "properties": {
    "displayName": "DbConnectionString",
    "value": "Server=tcp:myserver.database.windows.net;...",
    "secret": true
  }
}
```

**Secure - Key Vault reference:**
```json
{
  "type": "Microsoft.ApiManagement/service/namedValues",
  "name": "myAPIM/dbConnectionString",
  "properties": {
    "displayName": "DbConnectionString",
    "keyVault": {
      "secretIdentifier": "https://mykeyvault.vault.azure.net/secrets/DbConnectionString"
    },
    "secret": true
  }
}
```

---

## Debugging & Auditing Issues

### TA-000002/008/014: Remote Debugging Enabled

**Vulnerable:**
```json
{
  "type": "Microsoft.Web/sites/config",
  "name": "myApp/web",
  "properties": {
    "remoteDebuggingEnabled": true
  }
}
```

**Secure:**
```json
{
  "type": "Microsoft.Web/sites/config",
  "name": "myApp/web",
  "properties": {
    "remoteDebuggingEnabled": false
  }
}
```

---

### TA-000001: Diagnostic Logging Disabled

**Vulnerable:**
```json
{
  "type": "Microsoft.Web/sites/config",
  "name": "myApp/web",
  "properties": {
    "detailedErrorLoggingEnabled": false,
    "httpLoggingEnabled": false,
    "requestTracingEnabled": false
  }
}
```

**Secure:**
```json
{
  "type": "Microsoft.Web/sites/config",
  "name": "myApp/web",
  "properties": {
    "detailedErrorLoggingEnabled": true,
    "httpLoggingEnabled": true,
    "requestTracingEnabled": true
  }
}
```

---

### TA-000028: SQL Auditing Retention Too Short

**Vulnerable:**
```json
{
  "type": "Microsoft.Sql/servers/auditingSettings",
  "name": "myServer/default",
  "properties": {
    "state": "Enabled",
    "retentionDays": 30
  }
}
```

**Secure:**
```json
{
  "type": "Microsoft.Sql/servers/auditingSettings",
  "name": "myServer/default",
  "properties": {
    "state": "Enabled",
    "retentionDays": 90
  }
}
```

---

## Legacy Resource Issues

### TA-000030/031: Classic (non-ARM) Resources

**Vulnerable - Classic Compute:**
```json
{
  "type": "Microsoft.ClassicCompute/virtualMachines",
  "name": "myClassicVM"
}
```

**Secure - ARM Resource:**
```json
{
  "type": "Microsoft.Compute/virtualMachines",
  "name": "myVM",
  "properties": {
    "securityProfile": {
      "securityType": "TrustedLaunch"
    }
  }
}
```

**Vulnerable - Classic Storage:**
```json
{
  "type": "Microsoft.ClassicStorage/storageAccounts",
  "name": "myclassicstorage"
}
```

**Secure - ARM Storage:**
```json
{
  "type": "Microsoft.Storage/storageAccounts",
  "name": "mysecurestorage",
  "properties": {
    "minimumTlsVersion": "TLS1_2",
    "supportsHttpsTrafficOnly": true,
    "encryption": {
      "services": {
        "blob": { "enabled": true },
        "file": { "enabled": true }
      }
    }
  }
}
```

---

## Comprehensive Secure Template Example

Below is a fully secure web app template addressing multiple checks:

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "webAppName": {
      "type": "string"
    },
    "allowedOrigins": {
      "type": "array",
      "defaultValue": ["https://app.contoso.com"]
    }
  },
  "resources": [
    {
      "type": "Microsoft.Web/sites",
      "apiVersion": "2022-03-01",
      "name": "[parameters('webAppName')]",
      "location": "[resourceGroup().location]",
      "identity": {
        "type": "SystemAssigned"
      },
      "properties": {
        "httpsOnly": true,
        "siteConfig": {
          "minTlsVersion": "1.2",
          "ftpsState": "Disabled",
          "remoteDebuggingEnabled": false,
          "detailedErrorLoggingEnabled": true,
          "httpLoggingEnabled": true,
          "requestTracingEnabled": true,
          "cors": {
            "allowedOrigins": "[parameters('allowedOrigins')]"
          }
        }
      }
    }
  ]
}
```

**Equivalent Secure Bicep:**

```bicep
param webAppName string
param allowedOrigins array = ['https://app.contoso.com']

resource webApp 'Microsoft.Web/sites@2022-03-01' = {
  name: webAppName
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      remoteDebuggingEnabled: false
      detailedErrorLoggingEnabled: true
      httpLoggingEnabled: true
      requestTracingEnabled: true
      cors: {
        allowedOrigins: allowedOrigins
      }
    }
  }
}
```

---

## Quick Remediation Reference

| Issue | Property to Fix | Secure Value |
|-------|----------------|--------------|
| HTTPS not enforced | `httpsOnly` | `true` |
| Old TLS version | `minTlsVersion` | `"1.2"` |
| FTP allowed | `ftpsState` | `"FtpsOnly"` or `"Disabled"` |
| No managed identity | `identity.type` | `"SystemAssigned"` |
| CORS allows all | `cors.allowedOrigins` | Specific domains (not `*`) |
| Remote debugging on | `remoteDebuggingEnabled` | `false` |
| Logging disabled | `*LoggingEnabled` | `true` |
| Redis non-SSL | `enableNonSslPort` | `false` |
| TDE disabled | `transparentDataEncryption.state` | `"Enabled"` |
| No RBAC on AKS | `enableRBAC` | `true` |
