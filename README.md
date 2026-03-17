# ITSM (GitHub Pages) — Browser-only demo

This repository contains a fully client-side ITSM web application that runs entirely in the browser and can be hosted on **GitHub Pages**. No backend, no external services required.

## Features
- Signup / Login (stored in browser localStorage)
- Admin panel with invite token generation (copy & share token manually)
- Ticket management (create, assign, status, priority)
- Notes and Calendar modules
- Local AI Search (client-side summarizer)
- Dark / Light theme toggle
- All data stored in browser localStorage (per browser)

## How to deploy (only GitHub)
1. Create a new GitHub repository.
2. Add `index.html` and `README.md` to the repository (use GitHub web UI → Add file → Create new file).
3. Commit to the `main` branch.
4. In the repository, go to **Settings → Pages**.
   - Under **Build and deployment**, choose **Deploy from a branch**.
   - Select branch `main` and folder `/ (root)`.
   - Click **Save**. GitHub Pages will publish the site at `https://<your-username>.github.io/<repo-name>/`.
5. Open the published URL. The app runs entirely in your browser.

## Notes and limitations
- This demo stores all data locally in the browser. It is suitable for demos, prototypes, or offline use.
- There is **no server-side email** capability. Invite tokens are generated and must be shared manually.
- The local AI summarizer is a simple heuristic. To integrate a real AI, you would need a secure server-side proxy (not possible purely on GitHub Pages without exposing keys).
- For multi-user, persistent, or production use, migrate storage to a server or managed DB and add secure authentication.

## Reset data
To reset the demo data in your browser, open DevTools → Application → Local Storage → remove the key `itsm_data_v1` and `itsm_session_v1`.

## Security
This demo is for demonstration only. Password hashing is intentionally simple and not secure. Do not use this for real user accounts or sensitive data.
