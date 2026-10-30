# Importing from Confluence, Guru, GitHub wikis and Markdown folders

Bring an existing knowledge base into DumbSlab from a zip file. Members and admins can import under **Settings › Import**, and agents can do the same through MCP or the API.

## How it works

1. Export your content as a zip (see each format below).
2. Under **Settings › Import**, choose the zip. Your browser reads it and converts every page to Markdown. Nothing is sent yet.
3. Check the preview: the format it detected, how many pages, topics and attachments there are, what will be skipped and why, and roughly how many database writes and how much storage the import needs. You can rename the top topic, import the pages as drafts, and change the format if the detection got it wrong.
4. Choose **Import**. The page shows progress while images and files upload and pages are created. Keep the tab open until it finishes; you can use DumbSlab in another tab meanwhile.
5. The report lists what was imported, what was already there, and anything that failed, with the reason.

You can run the same import again at any time, for example after it stopped at the daily write limit or after you fixed a failed page. A page whose title already exists in the same topic is skipped, files you already uploaded are reused, and links between pages are completed. Nothing is duplicated.

## Formats

| Format | Export it | Becomes |
| --- | --- | --- |
| Confluence space | Cloud: **Space settings › Export space › HTML**. Data Center: **Space tools › Content tools › Export › HTML**. Download the zip. | The space is the top topic. Each page with child pages becomes a topic that holds that page and its children. The home page goes in the space's topic. |
| Guru collection | **Manage › Collection Settings**, then the **⋯** menu, then **Export Collection**. Guru emails you the zip. | The collection is the top topic. Folders, and sections inside folders, become topics. Cards become posts. Older exports with boards and board groups work too. |
| GitHub wiki | `git clone https://github.com/OWNER/REPO.wiki.git`, then zip the folder. | The top topic is "REPO wiki". `_Sidebar.md` arranges the pages: each heading, and each item with items under it, becomes a topic. Without a sidebar, folders become topics. |
| Markdown folder | Zip a folder of `.md` files, such as a repository's `docs` folder. | Each folder becomes a topic. The title comes from front matter `title:`, then a leading `# Heading`, then the file name. A folder's `README.md` or `index.md` is that topic's first post. |

### What comes across

- **Text and structure.** Headings, paragraphs, bold, italics, strikethrough, lists (numbered, nested, checklists), tables, code blocks with their language, quotes and horizontal rules.
- **Callouts.** Confluence's info, tip, note and warning macros and its editor's panels become callouts: info is `> [!NOTE]`, tip is `> [!TIP]`, note is `> [!WARNING]`, and warning is `> [!CAUTION]`.
- **Toggles.** Confluence expand macros become `<details>` toggles.
- **Links between pages.** These point at the imported posts, whether they use file names, Confluence page URLs, Guru `cards/<id>` links, `[[Wiki links]]` or relative `.md` links. Links to pages that aren't in the export keep their text.
- **Images and attachments.** They're uploaded and shown in the post. Confluence's export names files by id, so the importer takes the real names from the pages. In the preview you can leave out files that a Confluence page only lists under **Attachments** and doesn't show.
- **Videos and embeds.** A YouTube, Loom, Figma or similar frame becomes a link on its own line, which DumbSlab embeds.

### What doesn't come across

- **Confluence.** The HTML export has no comments, page history or blog posts, so neither does the import. Confluence's **XML** export is for moving between Confluence sites and isn't supported; export as HTML.
- **Guru.** Exports leave out archived cards. They carry no verification state or owners, so imported cards start unverified.
- **GitHub wikis.** Only Markdown pages are imported; pages in other markups, such as `.textile`, `.rst` or `.asciidoc`, are listed as skipped. `_Sidebar`, `_Footer` and `_Header` aren't posts. Images added through GitHub's web editor live on GitHub rather than in the clone, so they stay links to GitHub.
- **Everywhere.**
  - You are the author of every imported post, dated today.
  - Permissions don't carry over. Pages go into the topics the import names. A topic you can already see is reused, including a private one you're a member of; a new topic is visible to the whole workspace. To keep pages private, import into a private topic: create it first and give its name as the top topic.
  - Imports don't notify topic followers, and `@names` in imported text don't notify anyone.

## Limits

| What | Limit |
| --- | --- |
| Zip file | 1 GB and 200,000 files. Split a larger export (one space or collection at a time) or have an agent import it. |
| One page | 20 MB of source HTML or Markdown, and 2 MB of Markdown once converted. Larger pages are listed as skipped. |
| One image or file | 10 MB. Larger files are listed as skipped; the page still imports, showing the file's name instead. |
| Hosted plans | An imported page writes about 19 database rows, an uploaded file about 9, and fixing a page's links about 10. A free workspace may write 50,000 rows a day and store 50 MB. The preview compares the import with what this workspace has left. If the import reaches a limit, it stops; run it again once the allowance refills (it refills hour by hour) and it continues where it stopped. |

## Safety

The zip is read and converted entirely in your browser. HTML pages are parsed into an inert document that never runs scripts or loads images, and the conversion keeps only text, structure, links and images. Scripts, styles, frames, forms and event handlers are dropped, and links that aren't web, email or phone links lose their target. Raw HTML in Markdown pages loses scripts, styles and event handlers too, and the server sanitizes every post when it renders it.

## For agents

Many people migrate with an AI agent, which can work through MCP or the REST API with the same operations the web app uses. The steps:

1. **Read the export.** Unzip it and walk the files, using the layouts described above.
2. **Convert each page to Markdown.** DumbSlab's Markdown supports tables, checklists, footnotes and `> [!NOTE]` style callouts (`NOTE`, `TIP`, `IMPORTANT`, `WARNING`, `CAUTION`).
3. **Upload images and files** with `upload_file`, sending `name` and the bytes as `data_base64`, up to 10 MB each. Put the returned `path` in the Markdown: `![name](/files/<id>/<name>)` for an image, or `[name](/files/<id>/<name>)` for another file. Files uploaded without a `post_id` join the first of your posts that references them.
4. **Import the pages** with `import_documents`. Send 25 documents per call, staying under 8 MB per request. Each document has a `title`, the Markdown `content`, a topic path such as `Engineering/Runbooks` (missing topics are created) and a `status` (`published` by default, or `draft`). Pass `skip_existing: true` so a repeated call skips pages already imported. A failing document rolls back its whole call, so retry a failed batch one document at a time to find the problem page.
5. **Link the pages to each other.** `results` lists, in order, each document's post `id` and whether it was `skipped` because it already existed. Point links between pages at `/p/<id>`. For pages imported before their link targets existed, use `edit_post` with a `replace` edit afterwards.

An example `import_documents` call:

```json
{
  "skip_existing": true,
  "documents": [
    { "title": "Deploy the API", "topic": "Engineering/Runbooks", "content": "1. Merge to main.\n2. Watch the deploy.\n\n> [!WARNING]\n> Page the on-call engineer only for outages." },
    { "title": "Laptop setup", "topic": "Engineering/Onboarding", "content": "![Dock](/files/k3v9q0x2mz/dock.png)", "status": "draft" }
  ]
}
```

On hosted workspaces, a `429 write_limit` error means the daily write allowance is used up. Stop, and continue later with `skip_existing: true`. A `507 storage_full` error means the workspace is out of storage.

## Sources

These are the vendor documents the export formats are based on:

- Atlassian, [Export content to Word, PDF, HTML and XML](https://support.atlassian.com/confluence-cloud/docs/export-content-to-word-pdf-html-and-xml/) (Confluence Cloud) and the [Data Center equivalent](https://confluence.atlassian.com/doc/export-content-to-word-pdf-html-and-xml-139475.html).
- Guru, [Exporting content from Guru](https://help.getguru.com/docs/exporting-content-from-guru), [Collection exports](https://developer.getguru.com/docs/collection-exports) and [Importing a zip directory](https://developer.getguru.com/docs/importing-a-zip-directory).
- GitHub, [Adding or editing wiki pages](https://docs.github.com/en/communities/documenting-your-project-with-wikis/adding-or-editing-wiki-pages), [Editing wiki content](https://docs.github.com/en/communities/documenting-your-project-with-wikis/editing-wiki-content) and [Creating a footer or sidebar for your wiki](https://docs.github.com/en/communities/documenting-your-project-with-wikis/creating-a-footer-or-sidebar-for-your-wiki).
- MDN, [DecompressionStream](https://developer.mozilla.org/en-US/docs/Web/API/DecompressionStream/DecompressionStream). Reading zips needs its `deflate-raw` format: Chrome and Edge 103, Firefox 113, Safari 16.4 and later.

Two details come from real exports rather than these documents:

- Confluence Cloud stores attachments as `attachments/<pageId>/<attachmentId>`, often without a file extension.
- GitHub reads `[[A|B]]` as link text A pointing at page B, whatever its documentation says about the order.
