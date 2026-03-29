# UI and Documentation Style Guide

Use these terms consistently across UI, flash messages, documentation, and templates.

## Core Terms

- `Lost Request`
  - use for a lost-item report created by a user or staff
  - avoid: `Lost Item` when the record type is meant

- `Found Item`
  - use for an item recorded as found or handed in

- `Review Queue`
  - use for the review area for public lost submissions
  - avoid: `Lost Reviews`, `Lost Review Queue` unless a technical route name requires it

- `Mail`
  - use for the item-centric message workflow inside the app

- `Webmail`
  - use for the Roundcube mailbox UI

- `Ticket Mail Workflow`
  - use for the IMAP / SMTP ticketing setup in system settings
  - avoid: `IT-style mail ticket workflow`

- `AutoMail`
  - use as the feature name for rule-based automatic item mails

- `Public Lost Submission Confirmation`
  - use for the optional confirmation mail after `/report/lost`
  - avoid: `Public Lost Confirmation Mail`

## Status Terms

Use these exact labels:

- `Lost`
- `Maybe Found -> Check`
- `Found`
- `Waiting for answer`
- `To be answered`
- `Ready to send`
- `Handed over / Sent`
- `Lost forever`

## Writing Rules

- prefer short, task-oriented labels
- prefer `mail` over `e-mail` in UI labels unless the transport itself matters
- prefer sentence-style flash messages:
  - `Item created.`
  - `Ticket mail workflow settings updated.`
  - `The inbound mail was linked to the new item.`
- use title case for page titles and major navigation labels
- use consistent nouns for the same object across UI and docs

## Media Naming

Store UI assets under `docs/media/` using these names when possible:

- `mail-thread.png`
- `auto-mail-settings.png`
- `webmail-unassigned.gif`
