<h1 align="center" style="border-bottom: none">
    Nexus Certificate Manager AnyCA Gateway REST Plugin
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-prototype-3D1973?style=flat-square" alt="Integration Status: prototype" />
<a href="https://github.com/Keyfactor/nexus-certificate-manager-caplugin/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/nexus-certificate-manager-caplugin?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/nexus-certificate-manager-caplugin?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/nexus-certificate-manager-caplugin/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a> 
  ·
  <a href="#requirements">
    <b>Requirements</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=anycagateway">
    <b>Related Integrations</b>
  </a>
</p>


The Nexus Certificate Manager AnyCA Gateway REST Plugin integrates Keyfactor Command with Nexus Smart ID Certificate Manager via the Keyfactor AnyCA Gateway REST framework. It supports the following operations:

- **Certificate Enrollment** — issues certificates against a named Nexus CA token procedure (ProductID)
- **Certificate Revocation** — revokes certificates by CA request ID
- **Certificate Synchronization** — optional; see [Synchronization](#synchronization) below

## Compatibility

The Nexus Certificate Manager AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 25.2.0 and later.

## Support
The Nexus Certificate Manager AnyCA Gateway REST plugin is open source and there is **no SLA**. Keyfactor will address issues as resources become available. Keyfactor customers may request escalation by opening up a support ticket through their Keyfactor representative. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements

- The host URL for the Nexus Certificate Manager instance (including port), e.g. `https://192.168.1.10:8444`
- A PFX certificate for authenticating into Nexus Certificate Manager, accessible on the Gateway host
- The passphrase for the PFX certificate
- Server-side signing (VRO mode) must be enabled in the Nexus Protocol Gateway `api.properties`

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [Nexus Certificate Manager AnyCA Gateway REST plugin](https://github.com/Keyfactor/nexus-certificate-manager-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0` or `net8.0`) to the Extensions directory:


    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    ```

    > The directory containing the Nexus Certificate Manager AnyCA Gateway REST plugin DLLs (`net6.0` or `net8.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the Nexus Certificate Manager plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**

        The Keyfactor Command server must trust the CA chain used by the Nexus Certificate Manager. Identify the Root and/or Subordinate CA, download the certificate chain, and import it into the Command server certificate store before configuring the gateway.

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **Host** - The URI of the Nexus Certificate Manager API, including port. Example: https://192.168.1.10:8444 
        * **AuthCertificatePath** - The full path on the AnyCA Gateway host to the PFX certificate used for authenticating into Nexus Certificate Manager. 
        * **AuthCertPassword** - The password for the PFX authentication certificate. 
        * **Enabled** - Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow creation of the CA prior to configuration information being available. 
        * **SyncProcedureField** - Optional. Enables certificate synchronization. Set this to the name of the Nexus CA ExtendedCertSearch field (e.g. "field1") that your CA administrator has configured to store the issuing procedure name at enrollment time. When provided, Synchronize will read that field from each certificate to reconstruct its ProductID (procedure name). When omitted, Synchronize is disabled because the Nexus CA API does not natively return the issuing procedure with certificate records. NOTE: Configuring the Nexus CA to populate this field requires custom Java InputView development and AWB policy changes by a CA administrator. This configuration is outside the scope of Keyfactor support. 

2. TODO Certificate Template Creation Step is a required section

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.


## CA Connection Parameters

| Parameter | Required | Description |
|---|---|---|
| `Host` | Yes | The full URI of the Nexus Certificate Manager API, including port. Example: `https://192.168.1.10:8444` |
| `AuthCertificatePath` | Yes | The full path on the AnyCA Gateway host to the PFX certificate used for mutual TLS authentication. Example: `C:\certs\nexus-officer.pfx` |
| `AuthCertPassword` | Yes | The password for the PFX authentication certificate. |
| `Enabled` | Yes | Enables or disables gateway functionality. Set to `false` to defer configuration. |
| `SyncProcedureField` | No | Enables certificate synchronization. See [Synchronization](#synchronization) for full details. |

## Certificate Template (Product ID) Configuration

Each certificate template in Command must be associated with a **ProductID** that corresponds to a Nexus CA token procedure name. The plugin calls the `/procedures` endpoint at startup to populate the list of available procedures.

When enrolling, the procedure name from the selected template's ProductID is passed directly as the `procname` parameter in the enrollment request.

## Synchronization

By default, certificate synchronization is **disabled**. This is an intentional design decision: the Nexus CA REST API does not return the issuing procedure name in certificate list or detail responses, making it impossible to reconstruct the correct ProductID (procedure name) for each certificate during a sync. Without a valid ProductID, synchronized certificates cannot be associated with a certificate template in Command and will not appear in the UI.

### Enabling Synchronization via `SyncProcedureField`

Synchronization can be enabled by setting the optional `SyncProcedureField` CA connection parameter to the name of a Nexus CA `ExtendedCertSearch` field (e.g. `field1`) that your CA administrator has configured to store the issuing procedure name at enrollment time.

When `SyncProcedureField` is set:

- The sync operation pages through all certificates on the CA (500 per page)
- For each certificate, it reads the value of the specified `ExtendedCertSearch` field as the ProductID
- Certificates where the field is empty or missing are skipped and logged as warnings
- Only certificates with a resolvable ProductID are written to Command

### CA-Side Configuration Requirements

> ⚠️ **This configuration is entirely outside the scope of Keyfactor support.** The steps below describe what is required on the Nexus CA side. Keyfactor takes no responsibility for the correctness, stability, or ongoing maintenance of this configuration.

To populate an `ExtendedCertSearch` field with the procedure name at enrollment time, a Nexus CA administrator must:

1. **Develop a custom Java InputView** — InputViews are Java programs that run inside the Nexus Registration Authority (RA) and populate certificate attributes at issuance time. Custom InputViews must be compiled into a `.jar`, deployed to the CM server's `lib` directory, and registered in `cm.conf`. This requires working knowledge of the Nexus InputView API (documented in the CM Developers Guide).

2. **Configure the InputView to write the procedure name into an `ExtendedCertSearch` field** — the `ExtendedCertSearch` database table supports six generic fields (`field1`–`field6`). The InputView must be written to set the desired field to the issuing procedure name during enrollment.

3. **Associate the InputView with token procedures in the AWB** — using the Administrator's Workbench, a CA administrator must select the new InputView for each token procedure. This change must be signed by two administration officers in accordance with Nexus CM's four-eyes policy.

4. **Set `SyncProcedureField`** on the Keyfactor CA connection to the field name used (e.g. `field1`).

### Important Limitations

- Certificates issued **before** the CA-side configuration change was made will not have the field populated and will be skipped during sync.
- If the CA admin changes or repurposes the configured `ExtendedCertSearch` field, sync will silently produce incorrect results. The plugin will log warnings for affected certificates.
- The `SyncProcedureField` value must exactly match the field name (case-insensitive): `field1`, `field2`, `field3`, `field4`, `field5`, or `field6`. Any other value will cause all certificates to be skipped during sync.

## CHANGELOG

See [CHANGELOG.md](../CHANGELOG.md).


## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).