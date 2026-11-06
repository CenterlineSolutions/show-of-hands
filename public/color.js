/* Color math shared by the server (theme.css) and the Admin page (live contrast checks). */
(function (root) {
  const hex2rgb = h => { h = h.replace('#', ''); return [0, 2, 4].map(i => parseInt(h.slice(i, i + 2), 16)); };
  const rgb2hex = a => '#' + a.map(v => Math.round(Math.max(0, Math.min(255, v))).toString(16).padStart(2, '0')).join('');
  const lum = h => {
    const [r, g, b] = hex2rgb(h).map(v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const contrast = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
  const mix = (a, b, t) => { const A = hex2rgb(a), B = hex2rgb(b); return rgb2hex(A.map((v, i) => v + (B[i] - v) * t)); };
  // Nudge fg away from bg until the contrast ratio reaches min.
  const ensure = (fg, bg, min) => {
    const target = lum(bg) < 0.5 ? '#ffffff' : '#000000';
    let c = fg;
    for (let i = 0; i <= 20 && contrast(c, bg) < min; i++) c = mix(fg, target, i / 20);
    return c;
  };
  const DEFAULTS = { primary: '#d6277f', dark: '#15123a', light: '#f1eeff' };
  const isHex = v => typeof v === 'string' && /^#[0-9a-fA-F]{6}$/.test(v);

  // Everything the stylesheet needs, derived from the three colors the admin picks.
  function derive(t) {
    const p = t.primary, d = t.dark, l = t.light;
    const onHook = contrast('#ffffff', p) >= contrast(d, p) ? '#ffffff' : d;
    return {
      '--ink': d, '--ink-2': mix(d, '#ffffff', 0.08), '--mist': l, '--paper': '#ffffff',
      '--hook': p, '--hook-dark': mix(p, '#000000', 0.18), '--hook-bright': ensure(p, d, 4.5), '--on-hook': onHook,
      '--line': mix(l, d, 0.14), '--text': d, '--muted': ensure(mix(d, l, 0.35), l, 4.5),
    };
  }
  // Plain-language checks shown in Admin. min is the WCAG AA ratio for that use.
  function checks(t) {
    const v = derive(t);
    return [
      { label: 'Button text on the main color', ratio: contrast(v['--on-hook'], t.primary), min: 4.5 },
      { label: 'Main color on the light background (bars, percentages)', ratio: contrast(t.primary, t.light), min: 3 },
      { label: 'Dark color text on the light background', ratio: contrast(t.dark, t.light), min: 4.5 },
      { label: 'Light text on the dark big-screen background', ratio: contrast(t.light, t.dark), min: 4.5 },
    ];
  }
  const api = { hex2rgb, rgb2hex, lum, contrast, mix, ensure, derive, checks, isHex, DEFAULTS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.Color = api;
})(typeof window !== 'undefined' ? window : globalThis);
