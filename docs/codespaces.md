# Run ZT-FinGuard online with GitHub Codespaces (no Linux server needed)

1. On the repository page click **Code → Codespaces → Create codespace on main**.
2. Wait 5-10 minutes the first time. The terminal shows the build and finally **READY**
   with the demo users and their current authenticator codes.
3. Open the **PORTS** tab → row **ZT-FinGuard dashboard (8501)** → click the globe icon.
4. To share the link with your faculty: right-click that row → **Port Visibility → Public**.
   The link looks like `https://<name>-8501.app.github.dev`.

Useful commands in the codespace terminal:

| | |
|---|---|
| `make users` | demo logins + fresh 6-digit codes |
| `./deploy.sh --status` | health of all containers |
| `make test` | full end-to-end test suite |
| `cat .devcontainer/deploy.log` | full deployment log |

Notes
* The codespace stops after 30 minutes without use (GitHub setting: *Settings → Codespaces →
  Default idle timeout*, up to 4 hours). Starting it again restarts the stack automatically.
* The free GitHub plan includes 60 hours/month of a 2-core codespace (more with the GitHub
  Student Developer Pack). Stop it when you are done: **Code → Codespaces → … → Stop**.
* Falco (runtime detection) needs host kernel access and does not run inside Codespaces;
  automatic quarantine can still be demonstrated from the admin dashboard (manual isolate/release)
  and with `make test`.
