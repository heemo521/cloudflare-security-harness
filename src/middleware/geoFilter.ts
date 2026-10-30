import type { Middleware } from "../types";
import { blocked } from "../utils/respond";

/**
 * Country filtering based on Cloudflare's edge geolocation (request.cf.country).
 * "T1" is Cloudflare's code for Tor exit nodes and may be listed like a country.
 */
export const geoFilter: Middleware = async (ctx, next) => {
  const { blockedCountries, allowedCountries } = ctx.config;
  if (blockedCountries.length === 0 && allowedCountries.length === 0) return next();

  const country = ctx.cf.country?.toUpperCase();

  if (country && blockedCountries.includes(country)) {
    return blocked(ctx, 403, "geo-filter", `country ${country} is blocked`);
  }

  if (allowedCountries.length > 0) {
    if (!country) return blocked(ctx, 403, "geo-filter", "country unknown, allow list in effect");
    if (!allowedCountries.includes(country)) {
      return blocked(ctx, 403, "geo-filter", `country ${country} not on allow list`);
    }
  }

  return next();
};
