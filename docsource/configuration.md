## Overview

The Nexus Certificate Manager AnyCA Gateway REST Plugin integrates Keyfactor Command with Nexus Smart ID Certificate Manager via the Keyfactor AnyCA Gateway REST framework. It supports the following operations:

- **Certificate Enrollment** — issues certificates against a named Nexus CA token procedure (ProductID)
- **Certificate Revocation** — revokes certificates by CA request ID
- **Certificate Synchronization** — optional; see [Synchronization](#synchronization) below

## Requirements

- The host URL for the Nexus Certificate Manager instance (including port), e.g. `https://192.168.1.10:8444`
- A PFX certificate for authenticating into Nexus Certificate Manager, accessible on the Gateway host
- The passphrase for the PFX certificate
- Server-side signing (VRO mode) must be enabled in the Nexus Protocol Gateway `api.properties`

## Gateway Registration

The Keyfactor Command server must trust the CA chain used by the Nexus Certificate Manager. Identify the Root and/or Subordinate CA, download the certificate chain, and import it into the Command server certificate store before configuring the gateway.

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




