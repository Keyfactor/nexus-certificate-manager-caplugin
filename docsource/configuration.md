## Overview

The Nexus Certificate Manager AnyCA REST plugin connects Nexus Certificate Manager to Keyfactor Command via the AnyCA Gateway REST. It supports the following capabilities:
* Certificate Synchronization
* Certificate Enrollment
* Certificate Revocation

## Requirements

- The host URL for the instance of Nexus Certificate Manager
- A certificate in the pfx format to use for authentication into Nexus Certificate Manager, located on the Gateway Host
- The passphrase for the pfx certificate

## Gateway Registration

To enroll certificates, the Keyfactor Command server must trust the CA chain. Identify the Root and/or Subordinate CA used by Nexus Certificate Manager, then download and import the certificate chain into the Command Server certificate store.

## CA Connection

The certificate used by the gateway to authenticate into Nexus Certificate Manager must be copied to a location on the Gateway Host accessible by the gateway service.

## Certificate Template Creation Step

For this AnyCA Gateway, there is a single product type named "NexusCM".