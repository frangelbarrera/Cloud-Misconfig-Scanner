# GCP Storage - Least Privilege Permissions

To run the GCP Storage module in read-only mode, assign the following roles to the service account:

- **roles/storage.objectViewer**
- **roles/storage.legacyBucketReader**

These roles allow listing buckets, reading metadata, and checking IAM policies without modifying data.
