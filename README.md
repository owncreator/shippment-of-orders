# Natural Oils Courier & CRM Portal

A full-stack starter portal with a public shipment tracking site and an authenticated admin CRM. Built with Node.js, Express, SQLite, AES-256-GCM encryption for customer phone/address/internal notes, bcrypt password hashing, signed HttpOnly admin cookies, rate limits, security headers, audit logs, and PDF/CSV generation.

## Requirements
- Node.js 20 or newer
- npm

## Local setup

1. Extract the project folder.
2. Copy `.env.example` to `.env`.
3. Generate secrets:
   ```bash
   openssl rand -hex 32
   openssl rand -hex 32
   ```
   Use the first output as `JWT_SECRET` (a 64-character random secret is fine) and the second output as `DATA_ENCRYPTION_KEY` (exactly 64 hex characters).
4. Set a strong unique `ADMIN_PASSWORD` in `.env`. Set `ADMIN_EMAIL` to your own admin email. The initial admin is created on first server start if the database has no admins and valid secrets are configured.
5. Install and run:
   ```bash
   npm install
   npm start
   ```
6. Open `http://localhost:3000`. Admin login is at the top-right.

Do not deploy with example credentials. Keep `.env` and `data/` private, and back up the SQLite database securely. The encryption key must remain stable or previously encrypted fields cannot be decrypted. If the admin password is changed in `.env` after the first admin is already created, the existing database password hash does not automatically change.

## Included functionality
- Public tracking by tracking ID or order number.
- Admin login, dashboard metrics, shipment create/edit/search/filter, and status/event updates.
- Generated tracking IDs and order numbers when left blank.
- Private fields (phone, full address, internal notes) encrypted with AES-256-GCM before being stored.
- Password hashing with bcrypt, eight-hour signed session cookie, HttpOnly/SameSite=Strict cookie, login rate limit, Helmet headers, and admin audit log.
- PDF order receipt, consignment note, invoice-style draft, E-Way Bill data draft, and CSV export.
- Public tracking excludes customer email, phone, full address, declared value, GSTIN and internal notes.

## Important production and legal notes
- This project does **not** create an official government E-Way Bill. The included document is prominently described as a non-official draft. Official E-Way Bills must be generated/validated through the authorised GST portal or an approved integration with valid credentials and according to current rules.
- The invoice PDF is an internal invoice-style draft, not a certified GST-compliant tax invoice. Have a tax professional verify tax rates, HSN/SAC, seller details, place of supply, invoice numbering and GST rules before business use.
- A live carrier integration requires a contract/account and API documentation/credentials from the chosen courier provider. Environment variables are reserved for this integration, but carrier-specific API calls are not enabled until a provider is selected and implemented. Do not paste API secrets into frontend code.
- Before public production deployment, use HTTPS, a managed secret store, secure backups, monitoring, dependency updates, a data-retention policy, CSRF protection if auth flows are expanded, and a reviewed admin password-change/recovery process. Add GST seller profile and shipment origin details required for compliant documents.
- The initial-admin bootstrap uses `.env` credentials only when the database has no admin user. If you start once without secrets, configure the secrets and restart; the bootstrap can then create the initial admin in the still-empty database.

## Database
SQLite database is created automatically at `data/natural-oils.db`. Do not commit the database or `.env` file to version control.
