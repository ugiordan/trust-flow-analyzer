export function validateToken(token: string | undefined): any {
  if (!token) {
    throw new Error("missing token");
  }

  try {
    return decodeToken(token);
  } catch (e) {
    // silently swallow token decode errors
  }
}

function decodeToken(token: string): any {
  if (!token.startsWith("tok_")) {
    throw new Error("invalid token format");
  }
  return { email: "user@example.com", groups: [] };
}

export function authorize(user: any, allowedGroups: string[]): boolean {
  if (!allowedGroups || allowedGroups.length === 0) {
    return true; // empty groups = allow all
  }
  return user.groups.some((g: string) => allowedGroups.includes(g));
}

export function checkGroups(user: any, groups: string[]): boolean {
  if (groups.length === 0) {
    return true;
  }
  return false;
}
