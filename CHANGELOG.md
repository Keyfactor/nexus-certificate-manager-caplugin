### 1.1.0
* **Procedures as ProductIDs** — `GetProductIds()` now returns Nexus CA token procedure names dynamically from the `/procedures` endpoint rather than a single hardcoded value. Each certificate template in Command should be configured with a procedure name as its ProductID.
* **Pagination** — `Synchronize` and `GetCertificateList` now page through results in batches of 500, resolving failures that occurred when the max returned records limit (that defaults to 500) was reached.
* **Conditional synchronization** — `Synchronize` throws `NotSupportedException` with a clear explanation when `SyncProcedureField` is not configured. When configured, sync reads the specified `ExtendedCertSearch` field from each certificate to resolve its ProductID. See documentation for CA-side requirements.
* **`GetSingleRecord` fix** — `ProductID` is now resolved from the configured `ExtendedCertSearch` field instead of incorrectly using `CertId`.
* **`ValidateProductInfo`** — now validates that `ProductID` is non-empty.
* **Fixed deadlock risk** — replaced `.Result` with `.GetAwaiter().GetResult()` in `GetProductIds()`.
* **General Cleanup** — corrected "retreived" / "retreive" in log messages throughout.

### 1.0.0
* Initial release
