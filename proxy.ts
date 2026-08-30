import { NextResponse, type NextRequest } from "next/server";
import {
  isApiRequestAllowed,
  isApiRequestHostAllowed,
} from "@/lib/request-security";
import {
  isWebAuthenticated,
  isWebPasswordEnabled,
} from "@/lib/web-auth";

// Paths that stay reachable without authentication so the browser can show
// the login page and exchange the password for a session cookie.
const PUBLIC_PATHS = new Set([
  "/login",
  "/api/auth/web/login",
  "/api/auth/web/logout",
]);

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const isApiRequest = pathname === "/api" || pathname.startsWith("/api/");
  const isTrustedRequest = isApiRequest
    ? isApiRequestAllowed(request)
    : isApiRequestHostAllowed(request);

  if (!isTrustedRequest) {
    if (!isApiRequest) {
      return new NextResponse("Untrusted request", { status: 403 });
    }
    return NextResponse.json({ error: "Untrusted API request" }, { status: 403 });
  }

  const password = process.env.PI_WEB_PASSWORD;
  const requiresAuth = isWebPasswordEnabled(password) && !PUBLIC_PATHS.has(pathname);
  if (requiresAuth && !isWebAuthenticated(request, password)) {
    if (!isApiRequest) {
      // Send page requests to the login page instead of letting the browser
      // raise its native Basic Auth dialog.
      const loginUrl = new URL("/login", request.url);
      loginUrl.searchParams.set("next", `${pathname}${request.nextUrl.search}`);
      return NextResponse.redirect(loginUrl, { status: 302 });
    }
    // API calls get a plain 401 so fetch/EventSource clients can report the
    // failure without a dialog; curl & co. still use Basic Auth. Keep this
    // free of a WWW-Authenticate challenge: Chrome holds fetch/XHR responses
    // with a Basic challenge open while looking up credentials.
    return NextResponse.json({ error: "Authentication required" }, {
      status: 401,
      headers: { "Cache-Control": "no-store" },
    });
  }

  return NextResponse.next();
}

export const config = { matcher: ["/", "/api/:path*", "/login"] };
