## Overview

The Nexus Certificate Manager AnyCA REST plugin extends the capabilities of the Nexus Certificate Manager product to Keyfactor Command via the Keyfactor AnyCA Gateway REST. The plugin represents a fully featured AnyCA REST Plugin with the following capabilies:
* Certificate Synchronization
* Certificate Enrollment
* Certificate Revocation

## Requirements

- The host URL for the instance of Nexus Certificate Manager
- A certificate in the pfx format to use for authentication into Nexus Certificate Manager, located on the Gateway Host
- The passphrase for the pfx certificate

## Gateway Registration

In order to enroll certificates the Keyfactor Command server must trust the CA chain. Once you identify your Root and/or Subordinate CA used by the Nexus Certificate Manager platform, make sure to download and import the certificate chain into the Command Server certificate store

## CA Connection

The certificate used by the gateway for authenticating into the Nexus Certificate Manager will need to be copied to a location on the Gateway Host that is accessible by the gateway service.  The Certificate Path 

## Certificate Template Creation Step

For this AnyCA Gateway, there is a single product type named "NexusCM".