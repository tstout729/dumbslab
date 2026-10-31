# People sync (BambooHR)

People sync fills in profile details for the people already in your workspace from BambooHR: job title, department, location, work phone, pronouns and manager. They show on each person's profile page and in `get_user` (`details` and `manager`).

- **Matching.** A person here is matched to the BambooHR employee whose work email is the same as their DumbSlab email, ignoring upper and lower case.
- **What it changes.** Only those details. A sync never adds, deactivates or removes anyone, and never changes names, roles or avatars.
- **Who's left out.** Bots and deactivated accounts. Also employees with no work email, or a work email listed twice in BambooHR.
- **Who isn't found.** The sync lists BambooHR employees who aren't in the workspace (the first 200), and counts people here who have no BambooHR record. Invite or fix them yourself.
- **Manager.** The manager is linked when they're in the workspace too. When they aren't, no manager is shown.
- **Hidden fields.** If BambooHR doesn't let DumbSlab's BambooHR user see a field, that field is left as it was here.
- **Photos.** Photos aren't synced. BambooHR's photo links expire.

Only admins can set up, run or remove the sync (Settings › People sync, or the `get_people_sync`, `connect_people_sync`, `set_people_sync`, `sync_people` and `remove_people_sync` operations). It's available on every plan. It needs the server's connector key (`CONNECTOR_KEY` on Cloudflare, `DUMBSLAB_CONNECTOR_KEY` self-hosted; see [connected apps](connected-apps.md)). The BambooHR sign-in, API key and webhook private key are encrypted with it, and no operation ever returns them.

## Sign in with BambooHR or an API key

DumbSlab connects to BambooHR in one of two ways:

- **Sign in with BambooHR.** You give the company domain, approve DumbSlab in BambooHR, and you're done. This is the only way on hosted DumbSlab (dumbslab.com). It needs the host's BambooHR app; see [the operator guide](hosting/bamboohr-app.md).
- **An API key.** Self-hosted DumbSlab only.

BambooHR's [developer terms](https://www.bamboohr.com/legal/developer-terms-of-service) (§3.2 and §3.3) allow API keys only in systems a company runs on its own infrastructure. A service someone else hosts must use BambooHR's sign-in. So hosted DumbSlab refuses API keys. A self-hosted DumbSlab that your company runs itself may use one.

If the host has no BambooHR app and takes no API keys, Settings says People sync isn't available yet on this host.

## Set it up with Sign in with BambooHR

1. In DumbSlab, open **Settings › People sync**.
2. Enter the company domain and choose **Sign in with BambooHR**. For the domain, `acme`, `acme.bamboohr.com` and the address you sign in at (`https://acme.bamboohr.com/home`) all work.
3. BambooHR asks you to sign in and allow access. Allow it.

You come back to Settings › People sync. DumbSlab checks it can read employees, adds a webhook in BambooHR so changes there start a sync on their own, saves, and runs the first sync.

- You need to see employees' work email and job information in BambooHR, and to be allowed to add webhooks. The sync reads what you can see.
- The sign-in link works once, for 15 minutes, for the admin who started it, in the same browser.
- BambooHR's access token lasts an hour. DumbSlab renews it with the refresh token before it runs out. Only one request renews it at a time.
- To sync from another company, sign in again for it. Choosing **Sign in with BambooHR again** also replaces the saved sign-in.

If it doesn't work, Settings says why. The link back carries only a short code, such as `declined` or `no_access`.

## Set it up with an API key (self-hosted)

1. In BambooHR, open your name (top right) › **API Keys** › **Add New Key**, and copy the key. The key acts as you. You need to see employees' work email and job information, and to be allowed to add webhooks. A dedicated BambooHR user with that access also works.
2. In DumbSlab, open **Settings › People sync**. If Sign in with BambooHR is offered too, open **Use an API key instead**.
3. Enter the company domain and the API key, then choose **Save and sync**.

DumbSlab checks the key with BambooHR before saving it. A wrong key or company domain is refused with a message saying which, and nothing is saved. Then DumbSlab adds a webhook in BambooHR, so changes there start a sync on their own.

The result shows how many people were matched and updated, and which employees weren't found. Choose **Sync now** whenever you want to sync again.

## The webhook DumbSlab adds

- It posts to the workspace's webhook address, `https://<your workspace>/hooks/people`, in JSON.
- It's called "DumbSlab people sync (<your workspace's address>) ds-…". The `ds-…` tag is your workspace's own.
- It posts only which employee changed and the names of the fields that changed, never their values.
- It watches the fields a sync reads: work email, job title, department, location, work phone, reporting to, pronouns and status. It watches only those its BambooHR user can see.
- It belongs to the BambooHR user whose sign-in or API key added it. Only their credentials can delete it, and it stops working if that user is deactivated in BambooHR.
- Its private key is encrypted like the other credentials. No operation returns the key or the webhook's id.
- **Saving again keeps it** when nothing changed: same company, same credentials, same workspace address, and BambooHR still has it. DumbSlab asks BambooHR before keeping it.
- **Otherwise saving replaces it.** A new API key, a new sign-in, another company, a moved workspace, or a webhook someone deleted in BambooHR all get a new webhook. DumbSlab deletes the old one.
- Removing the sync deletes it.

### Old webhooks DumbSlab still has to delete

A webhook DumbSlab couldn't delete is harmless. It's event-based with no post fields, so a delivery carries only an employee's id and the names of the fields that changed, never their values. DumbSlab turns it away once the sync, or the webhook's private key, is gone.

DumbSlab still cleans these webhooks up. It doesn't rely on remembering each webhook's id, since a step that stops partway can lose one. Instead:

- Every webhook DumbSlab adds is named for the workspace: "DumbSlab people sync (<address>) ds-…", where the `ds-…` tag is the workspace's own and stays the same when the address changes.
- Before a save changes anything in BambooHR, DumbSlab keeps the credentials it's about to use and the ones it replaces (encrypted, refresh token included). Removing the sync keeps its credentials too.
- A cleanup pass lists the webhooks each set of credentials can see, and deletes every one with the workspace's tag that posts to `/hooks/people`, except the live one. Then it forgets those credentials.
- Passes run after saves, sign-ins and syncs, when Settings › People sync opens, and when a webhook DumbSlab doesn't recognize calls. So an orphaned webhook prompts its own deletion, even after the sync was removed.
- After a failed pass DumbSlab waits before the next: a minute, then twice as long each time, up to a day. Timeouts, rate limits (429) and BambooHR errors (5xx) never make it give up.
- It gives up only when the credentials are dead (BambooHR refuses fresh credentials with 401 or 403, or the company is gone; for an old sign-in, BambooHR refuses to renew it twice in a row, since a renewal still under way may hand over new tokens), or after 30 days. Then it says so in the activity log for admins, with the company and the webhook ids it knows, so someone can delete them in BambooHR by hand. It forgets the credentials.

Settings › People sync says when old webhooks are still being cleaned up. After signing in, it says when the webhook it replaced is still to be deleted (the `people_sync_notice=old_webhook` code).

If a save stops after BambooHR deleted the old webhook, Settings says so. Save again to add a new one.

**If the workspace moves to another address**, the webhook still posts to the old one, which no longer works. Settings › People sync says so. Choose **Save again** to move the webhook.

One change is saved at a time. While a save is under way, another save, or removing the sync, is refused with "try again in a minute". Removing the sync, or connecting another sign-in, API key or company, also waits while DumbSlab is renewing the BambooHR sign-in ("try again in a moment"), so no renewal of a connection is left running when it's retired.

Saving with new credentials (a new sign-in or API key) or another company starts a new connection. Syncs and renewals begun with the old one stop, even one that was only queued: they save nothing. So a sync can't fill in profiles, or store tokens, from the old company after you switched.

### If DumbSlab can't add the webhook

The sync is saved anyway, and Sync now works. Settings › People sync says why automatic syncing is off. Usually the BambooHR user isn't allowed to add webhooks, or can't see some of the fields. Give that user the access in BambooHR and choose **Save again**. Or add the webhook yourself:

1. In BambooHR, go to **Settings › Webhooks** and add a webhook. Its URL is the webhook address shown in Settings › People sync. Choose JSON, and watch Work Email, Job Title, Department, Location, Work Phone, Reporting To and Status.
2. Copy the webhook's **private key** into **Add the webhook yourself › Webhook private key** in Settings › People sync, and save.

While a private key you pasted is saved, DumbSlab adds no webhook of its own. To go back to DumbSlab's webhook, choose **Let DumbSlab add the webhook instead**, then delete yours in BambooHR. With the API, send `webhook_key` as an empty string to `set_people_sync`.

DumbSlab adds a webhook only when the workspace's address starts with `https://`. BambooHR sends webhooks to https addresses only, and it must be able to reach the address.

### How deliveries are checked

BambooHR signs each delivery: `X-BambooHR-Signature` is the hex HMAC-SHA256 of the request body followed by `X-BambooHR-Timestamp`, keyed with the private key. DumbSlab checks the delivery and then runs a full sync. It never uses the details in the delivery itself.

- A wrong signature gets a 401.
- So does a timestamp more than 5 minutes from now, in either direction. Keep the server's clock right.
- Each signature works once. A replay of a delivery already received gets a 409.
- If a sync is already running, the delivery is noted, and Settings says to sync again.

## How it works

- A sync calls BambooHR's List Employees endpoint: `GET https://<company>.bamboohr.com/api/v1/employees`. It asks for active employees only, up to 2,500 per page. It authenticates with the sign-in's access token, or with Basic authentication using the API key as the user name.
- A sync reads at most 3 pages, so **up to 7,500 active employees**. When it has to renew the sign-in first, it reads at most 2 pages (5,000). A bigger company gets a `partial` result, and the employees after those aren't updated.
- Only one sync runs at a time. The webhook's address works only while a private key is saved.
- Saving the sync calls BambooHR first. With a new sign-in, it exchanges the sign-in's code for tokens (`POST /token.php?request=token`). Then it checks access with one employee from List Employees, and reads the fields a webhook may watch (`GET /api/v1/webhooks/monitor_fields`). When it may keep the webhook, it looks it up (`GET /api/v1/webhooks/<id>`). Then it adds a webhook (`POST /api/v1/webhooks`) and deletes the old one (`DELETE /api/v1/webhooks/<id>`).
- Each change is a database write, so on hosted DumbSlab it counts against the plan's daily writes. A sync only writes people whose details changed.
- The details are kept in the `user_profiles` table. Removing the sync keeps the details already synced.
- Errors are explained in Settings: rejected credentials (401), missing permission (403), an unknown company domain (404), or rate limits (429).
