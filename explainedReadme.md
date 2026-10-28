# Certificate expiry report — explained

This is a plain-language guide for the spreadsheet the certificate checker produces. You do not need to know how certificates work to use it.

## What this is

Our OpenShift clusters use certificates to secure the connections to services and APIs. Every certificate has an end date. When that date passes, the service can stop working or show a security warning.

We have many clusters and many certificates. This report lists them in one spreadsheet so we can see which ones are coming due, and which app each one belongs to.

The checker only reads. It does not change anything on the clusters.

## What you get

A file named `cert-expiry.csv`. Open it in Excel.

Each row is one certificate that a service is using. One app can have more than one row if it has more than one certificate.

## How to read the columns

| Column | What it means |
|---|---|
| Service/API/Deployment | The app this certificate belongs to. Example: `checkout-api (deployment)`. |
| Issued By | Who signed the certificate. This is the authority that created it, not the app itself. |
| SAN | Other names this certificate is good for, besides the main one. Think of it as the list of addresses the certificate covers. |
| Issued OU | The team or department named on the certificate, if one was set. Many certificates leave this blank. |
| Validate Date | The day the certificate starts working. |
| Expired Date | The day the certificate stops working. |
| Days Left Until Expired | How many days remain. A negative number means it has already expired. |

## The one column that looks inconsistent: Issued By

Issued By is the full name of whoever signed the certificate. Different teams and different tools write that name differently, so the values will not all look the same. That is normal.

You may see:

- A short name, like `CN=internal-ca`
- A longer name with a company, like `CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US`
- More than one name (more than one `CN=`). Some authorities put two names on the certificate.
- A `serialNumber=` value. Some authorities include an ID in the name. That ID is part of the name. It is not a problem, and it is not the certificate's own serial number.

None of those differences mean the row is wrong. They only reflect how that particular certificate was created.

## What to look at first

Sort the spreadsheet by **Days Left Until Expired**, smallest number first.

- A negative number means the certificate has already expired. Those are the urgent ones.
- A small positive number means it is coming due soon.
- A large number means it is fine for now.

Then use **Service/API/Deployment** to see which app is affected, and **Expired Date** to see the exact day it stops.

## What this report does not include

- Certificates that are only used as trust bundles (the "who do I trust" files). Those do not expire in a way that takes a service down, so they are left out.
- Private keys. Those are never written to the file.

## How the file is produced

Someone logged into the cluster runs:

```bash
python3 openshift_cert_expiry.py -o cert-expiry.csv
```

That writes the spreadsheet. The scan finishes even if it finds expired certificates, so the file is always complete.
