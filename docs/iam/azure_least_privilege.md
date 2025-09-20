# Azure Blob Storage - Least Privilege Permissions

To run the Azure Blob module in read-only mode, assign the following roles to the service principal or user:

- **Storage Blob Data Reader** (built-in role)
- **Reader** (for account-level metadata)

These roles allow listing containers, reading properties, and checking access policies without modifying data.
