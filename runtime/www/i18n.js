/* Translation, keyed by the English string itself.
 *
 * WHY NOT SYMBOLIC KEYS. Retrofitting ~1,600 strings with invented keys
 * (`nav.manage_firmware`) is a large mechanical edit that breaks every existing
 * render check at once, and it leaves the source unreadable -- you can no longer
 * see what a line says without opening a catalog. Using the English text as the
 * key means a wrapped string still reads as itself, an UNtranslated string falls
 * back to exactly what it says today, and strings can be wrapped a page at a time
 * instead of in one unreviewable commit.
 *
 * The cost is that editing English copy orphans its translations. That is real, and
 * it is why tests/test_i18n_catalogs.py reports orphans rather than letting them rot
 * silently.
 *
 * UKRAINIAN AND RUSSIAN ARE SEPARATE LOCALES. Not variants of one another, not a
 * fallback chain between them. `uk` never falls back to `ru` and `ru` never falls
 * back to `uk`; both fall back to English. A missing Ukrainian string shows English,
 * never Russian. This is deliberate and a test enforces it.
 *
 * MACHINE TRANSLATION IS MARKED. Every catalog entry carries its provenance in the
 * file header, and anything not reviewed by a speaker says so. Safety text -- the
 * strings about flashing, bricking and irreversible writes -- is listed separately so
 * a reviewer can find it first.
 */
(function () {
  'use strict';

  var LOCALES = {
    en: { name: 'English', native: 'English' },
    uk: { name: 'Ukrainian', native: 'Українська' },
    ru: { name: 'Russian', native: 'Русский' },
    'zh-Hans': { name: 'Chinese (Simplified)', native: '简体中文' }
  };

  var current = 'en';
  var catalog = {};          // English string -> translated string
  var missing = Object.create(null);

  /* Translate. Unknown strings return themselves, so a page that has not been
     wrapped yet, or a locale that has not been filled in yet, both read as English
     rather than as a key or an empty box. */
  function t(s) {
    if (typeof s !== 'string' || !s) return s;
    if (current === 'en') return s;
    var hit = catalog[s];
    if (hit) return hit;
    missing[s] = (missing[s] || 0) + 1;
    return s;
  }

  /* What has not been translated in the active locale, for the catalog test and for
     anyone filling one in. Counts, so the busiest gaps are obvious. */
  function missingKeys() {
    return Object.keys(missing).sort(function (a, b) { return missing[b] - missing[a]; });
  }

  async function setLocale(code) {
    if (!LOCALES[code]) code = 'en';
    missing = Object.create(null);
    if (code === 'en') { current = 'en'; catalog = {}; return { ok: true, locale: 'en' }; }
    try {
      var r = await fetch('i18n/' + code + '.json', { cache: 'no-store' });
      if (!r.ok) throw new Error(String(r.status));
      var doc = await r.json();
      // The file carries metadata beside the strings; only `strings` is the catalog.
      catalog = (doc && doc.strings) || {};
      current = code;
      return { ok: true, locale: code, entries: Object.keys(catalog).length,
               provenance: doc && doc.provenance };
    } catch (e) {
      // A locale that will not load must not blank the application. Stay on English
      // and say so, rather than rendering a page of empty strings.
      current = 'en'; catalog = {};
      return { ok: false, locale: 'en', error: String(e && e.message || e) };
    }
  }

  function locale() { return current; }
  function locales() { return LOCALES; }

  window.i18n = { t: t, setLocale: setLocale, locale: locale, locales: locales,
                  missingKeys: missingKeys };
  // Short alias, because this wraps a lot of call sites.
  window.t = t;
})();
