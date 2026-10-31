# People sync (BambooHR)

People sync fills in profile details for the people already in your workspace from BambooHR: job title, department, location, work phone, pronouns and manager. They show on each person's profile page and in `get_user` (`details` and `manager`).

- **Matching.** A person here is matched to the BambooHR employee whose work email is the same as their DumbSlab email, ignoring upper and lower case.
- **What it changes.** Only those details. A sync never adds, deactivates or removes anyone, and never changes names, roles or avatars.
- **Who's left out.** Bots and deactivated accounts. Also employees with no work email, or a work email listed twice in BambooHR.
- **Who isn't found.** The sync lists BambooHR employees who aren't in the workspace (the first 200), and counts people here who have no BambooHR record. Invite or fix them yourself.
- **Manager.** The manager is linked when they're in the workspace too. When they aren't, no manager is shown.
- **Hidden fields.** If BambooHR doesn't let the API key's user see a field, that field is left as it was here.
- **Photos.** Photos aren't synced. BambooHR's photo links expire, and downloading a photo needs the API key.

Only admins can set up, run or remove the sync (Settings › People sync, or the `get_people_sync`, `set_people_sync`, `sync_people` and `remove_people_sync` operations). It's available on every plan. It needs the server's connector key (`CONNECTOR_KEY` on Cloudflare, `DUMBSLAB_CONNECTOR_KEY` self-hosted; see [connected apps](connected-apps.md)): the API key and the webhook's private key are encrypted with it, and no operation ever returns them.

## Set it up

1. In BambooHR, open your name (top right) › **API Keys** › **Add New Key**, and copy the key. The key acts as you. You need to see employees' work email and job information, and to be allowed to add webhooks. A dedicated BambooHR user with that access also works.
2. In DumbSlab, open **Settings › People sync**.
3. Enter the company domain and the API key, then choose **Save and sync**. For the domain, `acme`, `acme.bamboohr.com` and the address you sign in at (`https://acme.bamboohr.com/home`) all work.

That's all. DumbSlab checks the key with BambooHR before saving it. A wrong key or company domain is refused with a message saying which, and nothing is saved. Then DumbSlab adds a webhook in BambooHR, so changes there start a sync on their own.

The result shows how many people were matched and updated, and which employees weren't found. Choose **Sync now** whenever you want to sync again.

### The webhook DumbSlab adds

- It posts to the workspace's webhook address, `https://<your workspace>/hooks/people`, in JSON.
- It's called "DumbSlab people sync (<your workspace's address>)".
- It watches the fields a sync reads: work email, job title, department, location, work phone, reporting to, pronouns and status. It watches only those the API key's user can see.
- It belongs to the API key's user. It stops working if that user is deactivated in BambooHR.
- Its private key is encrypted like the API key. No operation returns the key or the webhook's id.
- Each save replaces it: DumbSlab deletes the one it added before and adds a new one. So changing the API key or the company domain moves the webhook too.
- Removing the sync deletes it.
- If BambooHR doesn't let DumbSlab delete an old webhook (the old key was revoked, say), the answer says so. That webhook's calls are turned away.

**If the workspace moves to another address**, the webhook still posts to the old one, which no longer works. Settings › People sync says so. Save the sync again to move the webhook.

### If DumbSlab can't add the webhook

The sync is saved anyway, and Sync now works. Settings › People sync says why automatic syncing is off. Usually the API key's user isn't allowed to add webhooks, or can't see some of the fields. Give that user the access in BambooHR and save again. Or add the webhook yourself:

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

- A sync calls BambooHR's List Employees endpoint: `GET https://<company>.bamboohr.com/api/v1/employees`. It asks for active employees only, up to 2,500 per page, using Basic authentication with the API key as the user name.
- A sync reads at most 3 pages, so **up to 7,500 active employees**. A bigger company gets a `partial` result, and employees after the first 7,500 aren't updated.
- Only one sync runs at a time. The webhook's address works only while a private key is saved.
- Saving the sync calls BambooHR first: one employee from List Employees to check the key, the fields a webhook may watch (`GET /api/v1/webhooks/monitor_fields`), then `POST /api/v1/webhooks` to add the webhook and `DELETE /api/v1/webhooks/<id>` to delete the old one. If someone else changes the sync while this happens, the save stops and deletes the webhook it just added. Save again.
- Each change is a database write, so on hosted DumbSlab it counts against the plan's daily writes. A sync only writes people whose details changed.
- The details are kept in the `user_profiles` table. Removing the sync keeps the details already synced.
- Errors are explained in Settings: a rejected key (401), missing permission (403), an unknown company domain (404), or rate limits (429).
