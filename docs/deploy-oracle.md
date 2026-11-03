# Live 24/7 deployment on Oracle Cloud Always Free (one command)

Oracle's Always Free tier includes an ARM VM with up to **4 CPU / 24 GB RAM, free forever**,
which is enough for all 11 ZT-FinGuard containers.

## 1. Create the account (once, ~10 minutes)

1. Go to **https://signup.cloud.oracle.com** and sign up.
   * **Home region:** pick **India South (Hyderabad)** or **India West (Mumbai)**. It can't be
     changed later, and Always Free VMs only run in the home region.
   * A debit/credit card is needed for identity verification only. Always Free resources are
     never charged.
2. Wait for the "account is ready" e-mail, then sign in at **https://cloud.oracle.com**.

## 2. Deploy (paste one command)

1. In the Oracle console click the **Cloud Shell** icon ( `>_` , top right) and wait for the prompt.
2. Paste:

```bash
curl -fsSL https://raw.githubusercontent.com/BALASUDHAN1807/zt-finguard/main/deploy/oracle-cloudshell.sh | bash
```

The script creates the network (only ports 22/80/443 open), launches the free ARM VM, installs
Docker, builds and starts everything, and finally prints:

```
✔ ZT-FinGuard is LIVE:  https://140-238-1-2.sslip.io
```

That address has a real Let's Encrypt certificate and works on any device, 24/7.
The demo logins and current 6-digit codes are printed at the end of the log.

## If it says "out of capacity"

Free ARM VMs are popular, and Oracle sometimes has none left in a region. Run the same
command again in 10–30 minutes; it tries every availability domain and smaller sizes
(2 CPU / 12 GB, then 1 CPU / 6 GB). Upgrading the account to **Pay As You Go** (Billing →
Upgrade) makes capacity much easier to get, and Always Free resources stay free.

## Later

| Task | In Cloud Shell |
|---|---|
| Demo logins + fresh codes | `ssh ubuntu@<IP> 'cd zt-finguard && make users'` |
| Health of every container | `ssh ubuntu@<IP> 'cd zt-finguard && ./deploy.sh --status'` |
| Redeploy latest code from GitHub | run the same `curl ... \| bash` command again |
