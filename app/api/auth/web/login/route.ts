import { NextResponse } from "next/server";
import {
  isWebPasswordEnabled,
  issueWebSessionCookieValue,
  verifyWebPassword,
  WEB_AUTH_COOKIE,
  WEB_SESSION_MAX_AGE_SECONDS,
} from "@/lib/web-auth";

export const dynamic = "force-dynamic";

function sessionCookie(value: string): string {
  return [
    `${WEB_AUTH_COOKIE}=${value}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${WEB_SESSION_MAX_AGE_SECONDS}`,
  ].join("; ");
}

export async function POST(request: Request) {
  const password = process.env.PI_WEB_PASSWORD;
  if (!isWebPasswordEnabled(password)) {
    return NextResponse.json({ ok: true, authenticated: true });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request" }, { status: 400 });
  }

  const supplied =
    typeof body === "object" && body !== null && "password" in body
      ? (body as { password?: unknown }).password
      : undefined;

  if (typeof supplied !== "string" || !verifyWebPassword(supplied, password)) {
    return NextResponse.json({ ok: false, error: "Incorrect password" }, { status: 401 });
  }

  const response = NextResponse.json({ ok: true, authenticated: true });
  response.headers.append("Set-Cookie", sessionCookie(issueWebSessionCookieValue(password)));
  return response;
}
