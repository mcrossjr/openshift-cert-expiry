# OpenShift certificate expiry

CLI scanner that uses `oc` to find TLS certificates, the workloads that mount them, and the Routes in front of those workloads. It writes a CSV with an `expiration` column (`YYYY-MM-DD`, the certificate notAfter date).

Python 3.9+ and the standard library only. `oc` must already be logged in. The account needs get/list on secrets. `cluster-reader` cannot read secrets.

A Route does not point at a Deployment. It points at a Service, and that Service selects pods by label. The certificate is either in a Secret those pods mount, written on the Route, or referenced by `spec.tls.externalCertificate`.

## Run

```bash
python3 openshift_cert_expiry.py
python3 openshift_cert_expiry.py -o cert-expiry.csv
python3 openshift_cert_expiry.py --all-contexts --threshold-days 45 --probe -o cert-expiry.csv
python3 openshift_cert_expiry.py -n payments -n identity --csv cert-expiry.csv
```

`-o cert-expiry.csv` prints the report and writes the file. `--csv cert-expiry.csv` writes only the file. `--csv` with no path prints CSV on stdout.

Exit 2 when any certificate is expired or inside the warning window. Exit 1 means `oc` failed or the arguments are wrong.

## CSV columns

`context`, `namespace`, `name`, `expiration`, `days_left`, `status`, `source`, `key`, `role`, `subject`, `issuer`, `sans`, `serial`, `workloads`, `services`, `routes`, `termination`, `probe`, `notes`

`expiration` is the notAfter date in UTC.
