# People sync (BambooHR)

People sync fills in profile details for the people already in your workspace from BambooHR: job title, department, location, work phone, pronouns and manager. They show on each person's profile page and in `get_user` (`details` and `manager`).

- **Matching.** A person here is matched to the BambooHR employee whose work email is the same as their DumbSlab email, ignoring upper and lower case.
- **What it changes.** Only those details. A sync never adds, deactivates or removes anyone, and never changes names, roles or avatars.
- **Who's left out.** Bots and deactivated accounts. Also employees with no work email, or a work email listed twice in BambooHR.
- **Who isn't found.** The sync lists BambooHR employees who aren't in the workspace (the first 200), and counts people here who have no BambooHR record. Invite or fix them yourself.
- **Manager.** The manager is linked when they're in the workspace too. When they aren't, no manager is shown.
- **Hidden fields.** If BambooHR doesn't let the API key's user see a field, that field is left as it was here.
- **Photos.** Photos aren't synced. BambooHR's photo links expire, and downloading a photo needs the API key.

Only admins can set up, run or remove the sync (Settings › People sync, or the `get_people_sync`, `set_people_sync`, `sync_people` and `remove_people_sync` operations). It's available on every plan. It needs the server's connector key (`CONNECTOR_KEY` on Cloudflare, `DUMBSLAB_CONNECTOR_KEY` self-hosted; see [connected apps](connected-apps.md)): the API key and webhook key are encrypted with it, and no operation ever returns them.

## Set it up

1. In BambooHR, open your name (top right) › **API Keys** › **Add New Key**, and copy the key. The key acts as you, so you need to be able to see employees' work email and job information. A dedicated BambooHR user with read access to those fields also works.
2. In DumbSlab, open **Settings › People sync**.
3. Enter the company domain (`acme` for `acme.bamboohr.com`) and the API key, then choose **Save and sync**.

The result shows how many people were matched and updated, and which employees weren't found. Choose **Sync now** whenever you want to sync again.

### Sync automatically when BambooHR changes (optional)

1. In BambooHR, go to **Settings › Webhooks** and add a webhook. Its URL is the webhook address shown in Settings › People sync: `https://<your workspace>/hooks/people`. Choose the fields to watch (job title, department, location, work email, reports to, work phone, pronouns), or use an employee-updated event.
2. Copy the webhook's **private key** into **Webhook private key** in Settings › People sync, and save.

BambooHR signs each delivery: `X-BambooHR-Signature` is the hex HMAC-SHA256 of the request body followed by `X-BambooHR-Timestamp`, keyed with the private key. DumbSlab checks it and then runs a full sync. It never uses the details in the delivery itself. A delivery with a wrong signature gets a 401. If a sync is already running, the delivery is noted, and Settings says to sync again.

## How it works

- A sync calls BambooHR's List Employees endpoint: `GET https://<company>.bamboohr.com/api/v1/employees`. It asks for active employees only, up to 2,500 per page, using Basic authentication with the API key as the user name.
- A sync reads at most 3 pages, so **up to 7,500 active employees**. A bigger company gets a `partial` result, and employees after the first 7,500 aren't updated.
- Only one sync runs at a time. The webhook's address works only while a private key is saved.
- Each change is a database write, so on hosted DumbSlab it counts against the plan's daily writes. A sync only writes people whose details changed.
- The details are kept in the `user_profiles` table. Removing the sync keeps the details already synced.
- Errors are explained in Settings: a rejected key (401), missing permission (403), an unknown company domain (404), or rate limits (429).
