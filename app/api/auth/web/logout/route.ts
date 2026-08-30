import { NextResponse } from "next/server";
import { WEB_AUTH_COOKIE } from "@/lib/web-auth";

export const dynamic = "force-dynamic";

export async function POST() {
  const response = NextResponse.json({ ok: true });
  response.headers.append(
    "Set-Cookie",
    [
      `${WEB_AUTH_COOKIE}=`,
      "Path=/",
      "HttpOnly",
      "SameSite=Lax",
      "Max-Age=0",
    ].join("; "),
  );
  return response;
}
