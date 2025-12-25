# Node.js JWT Authentication Playground (Elysia Version)

![Node.js](https://img.shields.io/badge/node-%3E%3D22-green)
![Elysia](https://img.shields.io/badge/elysia-1.4.x-purple)
![JWT](https://img.shields.io/badge/jwt-enabled-blue)
![Tailwind](https://img.shields.io/badge/tailwind-styled-yellow)
![Render](https://img.shields.io/badge/render-deployed-brightgreen)

Minimal **JWT authentication playground** built on **Node.js**, **Elysia**, and **HttpOnly cookies**, with a modern **Tailwind CSS UI**.

* Uses **Elysia** as the HTTP framework with `@elysiajs/node` adapter
* Fully **JWT-based authentication** with **access + refresh tokens**
* **HttpOnly cookies** for secure token storage
* **Tailwind CSS** for responsive, modern UI
* Fully written in **TypeScript** for type safety
* Single-file frontend served via Elysia — no build tools required
* Frontend is a **single-page application (SPA)** served directly by Elysia, requiring **no frontend build tools**.

---

## Run Locally

1. Install dependencies:

```bash
npm install
```

2. Run the server:

```bash
npm run dev
```

3. Open in your browser:

[http://localhost:8080/](http://localhost:8080/)

---

## Features

* **Login / logout** with email & password
* **Access tokens** (short-lived) and **refresh tokens** (long-lived)
* **HttpOnly cookies** for secure token storage
* **Protected routes**: `/me` for authenticated users, `/admin` for admins only
* **Role-based access control**
* **Refresh token endpoint** for seamless session extension
* Refresh tokens are stored **in-memory only** and are not persisted in a database; for production, consider using a persistent store.
* **Rate limiting** per IP to prevent abuse
* Modern **Tailwind CSS UI** for interactive testing

---

## Endpoints

| Path            | Method | Description                                  |
| --------------- | ------ | -------------------------------------------- |
| `/`             | GET    | Serves the HTML frontend                     |
| `/auth/login`   | POST   | Authenticates user and sets HttpOnly cookies |
| `/auth/refresh` | POST   | Issues new access token using refresh token  |
| `/auth/logout`  | POST   | Clears cookies and revokes refresh token     |
| `/me`           | GET    | Returns info about authenticated user        |
| `/admin`        | GET    | Admin-only endpoint, requires admin role     |

---

## Example Usage

1. Open [http://localhost:8080/](http://localhost:8080/) in a browser.
2. Enter credentials (`admin@local` / `admin` or `user@local` / `user`).
3. Click **Login**.
4. Test `/me` and `/admin` buttons — `/admin` restricted to admins.
5. Click **Logout** to clear session.

---

## Client-side Notes

* HttpOnly cookies prevent direct JS access to tokens.
* Uses **fetch with credentials** to include cookies automatically.
* JSON responses displayed in a **Tailwind-styled `<pre>`** for debugging.
* Logout clears both access and refresh tokens.

---

## Server-side Notes

* JWT **access tokens** contain `sub` (user ID) and `role`.
* JWTs are signed using a secret key; in production, the secret should be set via an **environment variable** for security.
* Refresh tokens stored server-side in-memory for revocation.
* **Rate limiting** implemented per IP address.
* Protected routes check **user authentication and role**.
* TypeScript provides type safety for tokens, users, and routes.

---

## Technology Stack

* **Node.js >=22** – Runtime
* **Elysia 1.4.x** – Lightweight HTTP framework
* **@elysiajs/node** – Node.js adapter
* **@elysiajs/html** – Middleware to serve HTML
* **jsonwebtoken 9.x** – JWT support
* **Tailwind CSS** – Modern responsive UI styling
* **TypeScript 5.9.x** – Static typing

---

## TODO / Future Improvements

- [ ] Add persistent storage for refresh tokens
- [ ] Implement hashed passwords
- [ ] Add email verification
- [ ] Add user registration
- [ ] Enhance frontend UI/UX
- [ ] Add logging and monitoring for server requests and authentication events

---

## Notes

* Designed as a **learning and testing playground** for JWT authentication.
* Fully **one-file frontend and backend** for simplicity.
* Easily extendable for small projects or experiments.
* Uses **vanilla JS + Tailwind CSS**, no frontend build tools required.
* Mobile-friendly and responsive.

---

## Test Credentials

* **Admin:** `admin@local` / `admin`
* **User:** `user@local` / `user`

---

## Deploy in 10 seconds

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)
