<h1 align="center" style="border-bottom: none">
    Nexus Certificate Maanager   Gateway AnyCA Gateway REST Plugin
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


The Nexus Certificate Manager AnyCA REST plugin extends the capabilities of the Nexus Certificate Manager product to Keyfactor Command via the Keyfactor AnyCA Gateway REST. The plugin represents a fully featured AnyCA REST Plugin with the following capabilies:
* Certificate Synchronization
* Certificate Enrollment
* Certificate Revocation

## Compatibility

The Nexus Certificate Maanager   Gateway AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 25.2.0 and later.

## Support
The Nexus Certificate Maanager   Gateway AnyCA Gateway REST plugin is open source and there is **no SLA**. Keyfactor will address issues as resources become available. Keyfactor customers may request escalation by opening up a support ticket through their Keyfactor representative. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements

- The host URL for the instance of Nexus Certificate Manager
- A certificate in the pfx format to use for authentication into Nexus Certificate Manager, located on the Gateway Host
- The passphrase for the pfx certificate

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [Nexus Certificate Maanager   Gateway AnyCA Gateway REST plugin](https://github.com/Keyfactor/nexus-certificate-manager-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0` or `net8.0`) to the Extensions directory:


    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    ```

    > The directory containing the Nexus Certificate Maanager   Gateway AnyCA Gateway REST plugin DLLs (`net6.0` or `net8.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the Nexus Certificate Maanager   Gateway plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**

        In order to enroll certificates the Keyfactor Command server must trust the CA chain. Once you identify your Root and/or Subordinate CA used by the Nexus Certificate Manager platform, make sure to download and import the certificate chain into the Command Server certificate store

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **Host** - The path to the Nexus CM server, including port 
        * **AuthCertificatePath** - The path to the PFX certificate for authenticating into Nexus CM 
        * **AuthCertPassword** - The password for the authentication certificate 
        * **Enabled** - Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow creation of the CA prior to configuration information being available. 

2. For this AnyCA Gateway, there is a single product type named "NexusCM".

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.


## CA Connection

The certificate used by the gateway for authenticating into the Nexus Certificate Manager will need to be copied to a location on the Gateway Host that is accessible by the gateway service.  The Certificate Path


## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).