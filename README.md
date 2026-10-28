# OpenShift certificate expiry

CLI scanner that uses `oc` to find which service certificate expires, and which deployment it belongs to.

Python 3.9 or newer. No extra packages. `oc` must already be logged in. The account needs permission to read secrets. `cluster-reader` cannot.

## Run

```bash
python3 openshift_cert_expiry.py -o cert-expiry.csv
```

That prints a report and writes `cert-expiry.csv`. `--csv cert-expiry.csv` writes only the file.

## Spreadsheet columns

The CSV is for people who do not work with certificates. One row is the certificate a service actually uses. CA bundles are left out.

| Column | Meaning |
|---|---|
| Service/API/Deployment | The app the certificate belongs to |
| Issued By | The full name of whoever signed the certificate |
| SAN | Other names the certificate is valid for |
| Issued OU | The department or team named on the certificate, if any |
| Validate Date | The day the certificate starts working |
| Expired Date | The day the certificate stops working |
| Days Left Until Expired | How many days remain. A negative number means it has already expired |

A finished scan exits 0 even when a certificate is already expired or inside 30 days. Those rows are still in the CSV. Exit 1 means `oc` failed.
