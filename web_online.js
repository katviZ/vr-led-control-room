/* VR LED Control Room · online (encrypted) mode.
   - decrypt(): PBKDF2-SHA256 -> AES-256-GCM -> gzip -> JSON (payload built by tools/build_web.py)
   - inspectNova(): reads a NovaStar .rcfgx entirely in the browser (nothing is uploaded).
   Mirrors ledroom/nova.py, ledroom/lint.py and ledroom/pitch.py — keep them in step. */
window.VRO = (() => {
  "use strict";
  const te = new TextEncoder(), td = new TextDecoder();
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const hex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, "0")).join("");

  async function decrypt(pass) {
    const E = window.VR_ENC;
    const base = await crypto.subtle.importKey("raw", te.encode(pass), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64(E.salt), iterations: E.iter, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(E.iv) }, key, b64(E.ct));
    const ds = new Blob([plain]).stream().pipeThrough(new DecompressionStream("gzip"));
    return JSON.parse(await new Response(ds).text());
  }

  /* ---------------- zip ---------------- */
  const MAX_UNPACKED = 200 * 1024 * 1024;
  async function inflateRaw(u8) {
    return new Uint8Array(await new Response(new Blob([u8]).stream().pipeThrough(new DecompressionStream("deflate-raw"))).arrayBuffer());
  }
  async function unzip(buf) {
    const dv = new DataView(buf), u8 = new Uint8Array(buf);
    let eocd = -1;
    for (let i = buf.byteLength - 22; i >= Math.max(0, buf.byteLength - 66000); i--) {
      if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error("this isn't a NovaStar .rcfgx (no zip directory)");
    const n = dv.getUint16(eocd + 10, true);
    let p = dv.getUint32(eocd + 16, true), total = 0;
    const out = [];
    for (let k = 0; k < n; k++) {
      if (dv.getUint32(p, true) !== 0x02014b50) throw new Error("damaged zip directory");
      const method = dv.getUint16(p + 10, true), csize = dv.getUint32(p + 20, true), usize = dv.getUint32(p + 24, true);
      const nl = dv.getUint16(p + 28, true), el = dv.getUint16(p + 30, true), cl = dv.getUint16(p + 32, true);
      const lho = dv.getUint32(p + 42, true);
      const name = td.decode(u8.subarray(p + 46, p + 46 + nl));
      total += usize;
      if (total > MAX_UNPACKED) throw new Error("file unpacks to an unrealistic size; refusing to open it");
      const start = lho + 30 + dv.getUint16(lho + 26, true) + dv.getUint16(lho + 28, true);
      const data = u8.subarray(start, start + csize);
      let bytes;
      if (method === 0) bytes = data.slice();
      else if (method === 8) bytes = await inflateRaw(data);
      else throw new Error("unsupported compression inside the file");
      out.push({ name, bytes });
      p += 46 + nl + el + cl;
    }
    return out;
  }

  /* ---------------- RCCB ---------------- */
  function parseRCCB(b) {
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    if (td.decode(b.subarray(0, 4)) !== "RCCB") throw new Error("card instructions are not in NovaStar RCCB format");
    const total = dv.getUint32(4, true), ck = dv.getUint16(8, true), ver = dv.getUint16(10, true);
    let sum = 0;
    for (let i = 64; i < b.length; i++) sum += b[i];
    const recs = [];
    let off = 64;
    while (off < b.length) {
      if (off + 32 > b.length) throw new Error(`truncated record header at byte ${off}`);
      const rlen = dv.getUint32(off, true), addr = dv.getUint32(off + 6, true), dlen = dv.getUint32(off + 10, true);
      if (rlen < 32 || off + rlen > b.length || dlen !== rlen - 32) throw new Error(`bad record at byte ${off}`);
      recs.push({ addr, data: b.subarray(off + 32, off + rlen) });
      off += rlen;
    }
    return { records: recs, checksum_ok: ((sum + 0x5555) & 0xffff) === ck, length_ok: total === b.length, version: ver };
  }
  function u16s(data) {
    const n = data.length >> 1, dv = new DataView(data.buffer, data.byteOffset, n * 2), v = new Array(n);
    for (let i = 0; i < n; i++) v[i] = dv.getUint16(i * 2, true);
    return v;
  }
  function gammaFromTable(data) {
    const v = u16s(data), n = v.length;
    if (n < 16) return null;
    const top = Math.max(...v);
    if (!top) return null;
    const est = [];
    for (const i of [Math.floor(n / 4), Math.floor(n / 2), Math.floor(3 * n / 4)]) {
      const x = i / (n - 1), y = v[i] / top;
      if (y > 0 && y < 1) est.push(Math.log(y) / Math.log(x));
    }
    return est.length ? Math.round((est.reduce((a, b) => a + b, 0) / est.length) * 100) / 100 : null;
  }

  /* ---------------- XML helpers ---------------- */
  const kid = (el, tag) => { for (const c of el.children) if (c.tagName === tag) return c; return null; };
  function gx(root, path) {
    if (path.startsWith(".//")) { const e = root.getElementsByTagName(path.slice(3))[0]; return e ? e.textContent.trim() : ""; }
    let e = root;
    for (const t of path.split("/")) { e = e && kid(e, t); }
    return e ? e.textContent.trim() : "";
  }
  const int = (s) => (/^-?\d+$/.test(s) ? parseInt(s, 10) : null);
  const tri = (s) => (s === "true" ? true : s === "false" ? false : null);
  const b64bytes = (s) => { try { return [...atob(s || "")].map((c) => c.charCodeAt(0)); } catch (e) { return []; } };

  /* ---------------- pitch (ledroom/pitch.py) ---------------- */
  const STD = [0.9375, 1.2, 1.25, 1.5, 1.53, 1.56, 1.667, 1.86, 1.953, 2.0, 2.5, 2.604, 2.97, 3.076, 3.91, 4.0, 4.81, 5.0, 6.0, 6.67, 8.0, 10.0];
  const NAME_RE = /(?<![A-Za-z0-9])[Pp]\s?(\d{1,2}(?:\.\d{1,4})?)(?!\d)(?!\.\d)/;
  function pitchGuess(cols, name) {
    let n = null;
    const m = NAME_RE.exec(name || "");
    if (m) { const v = parseFloat(m[1]); if (v >= 0.5 && v <= 20) n = v; }
    let w = null;
    if (cols) {
      const p = 320 / cols, best = STD.reduce((a, s) => (Math.abs(p - s) / s < Math.abs(p - a) / a ? s : a));
      if (Math.abs(p - best) / best < 0.03) w = best;
    }
    if (n) {
      let src = "from file name";
      if (w && Math.max(w, n) / Math.min(w, n) > 1.05 && Math.max(w, n) / Math.min(w, n) < 1.6) src += ` (module width suggests P${w} if 320 mm)`;
      return { value: n, source: src };
    }
    return w ? { value: w, source: "estimate, assumes 320 mm module" } : null;
  }

  /* ---------------- spec + checks (ledroom/nova.py, ledroom/lint.py) ---------------- */
  const PWM = ["DP3", "DP5", "ICND1", "ICND2", "ICN2053", "ICN2055", "ICN2065", "ICN2153", "ICN2163", "ICN2165",
    "ICN2263", "SM16158", "SM16159", "SM16169", "SM16237", "SM16238", "SM16259", "SM16269", "SM16359",
    "SM16369", "SM16380", "SM16388", "SM16389", "SM16395", "SM16509", "C83", "FM63", "HX88", "MBI5153", "MBI5252",
    "MBI5253", "MBI5264", "MBI5353", "MY9868"];
  const OLD = ["ICN2038", "ICN2045", "MBI5124", "MBI5024", "SM16126", "ICN2012"];

  function spec(root, rc, name, chips) {
    const g = (p) => gx(root, p);
    const code = int(g("StandardLedModuleProp/DriverChipType/ChipCode"));
    const chip = code != null ? (chips[String(code)] || `code ${code}`) : "";
    const cols = int(g("StandardLedModuleProp/ModulePixelCols")), rows = int(g("StandardLedModuleProp/ModulePixelRows"));
    const refnum = int(g("RefNumPerVs"));
    const pwm = PWM.some((p) => chip.toUpperCase().startsWith(p));
    const gh = int(g("GammaValue"));
    let gt = null;
    if (rc) { const r = rc.records.find((x) => x.addr === 0x05000000); if (r) gt = gammaFromTable(r.data); }
    const br = int(g("Brightness"));
    let gmod = parseFloat(g(".//GammaModulus"));
    if (!isFinite(gmod) || !gmod) gmod = null;
    return {
      card: g("ConfigFileVersion/HWProgramVersionList/ScanBoardVersionInfo/ScanBoardName"),
      card_program: g("ConfigFileVersion/HWProgramVersionList/ScanBoardVersionInfo/ProgramVersion"),
      software: g("RCFGXVersion").split("-")[0] || null,
      driver_chip: chip, driver_chip_code: code,
      decoder: g("StandardLedModuleProp/DecType").replace("Decode", ""),
      module_px: cols && rows ? `${cols}x${rows}` : null,
      pitch: pitchGuess(cols, name),
      scan: g("StandardLedModuleProp/ScanType").replace("Scan_", "1/"),
      card_load_px: `${g("Width")}x${g("Height")}`,
      module_grid: `${g("ModuleCols")}x${g("ModuleRows")}`,
      data_groups: int(g("PhysicalDataGroupNum")),
      refresh_hz: refnum && pwm ? refnum * 60 : null,
      refresh_note: pwm ? null : "not calculated for this chip",
      gray_bits: int(g("GrayDepth")),
      gamma_header: gh === 254 ? gmod : gh ? gh / 10 : null,
      gamma_table: gt,
      brightness_pct: br != null ? Math.round(br / 255 * 100) : null,
      calibration: tri(g("IsEnableCalibration")),
      irregular_cabinet: tri(g("IsIrRegular")),
      rotation: g("CabinetRotateAngle"),
      records: rc ? rc.records.length : 0,
      checksum_ok: rc ? rc.checksum_ok && rc.length_ok : null,
    };
  }
  const F = (level, title, detail = "") => ({ level, title, detail });
  function checks(s, problems) {
    const out = problems.map((p) => F("red", "File is damaged", p));
    if (s.checksum_ok === false) out.push(F("red", "Checksum does not match", "The card-instruction part of the file has been altered or damaged. Don't load it."));
    const g = s.gamma_table;
    if (g != null) {
      if (g < 0.9) out.push(F("amber", `Unusual gamma curve (≈${g})`, "The stored curve lifts dark tones, so blacks may look grey. Check on a wall before using."));
      else if (g < 1.3) out.push(F("amber", `Gamma curve is flat (≈${g.toFixed(1)})`, "Pictures may look washed out, unless the driver chip applies gamma itself. Check on a wall."));
      else if (g > 3.2) out.push(F("amber", `Very steep gamma (≈${g})`, "Dark areas may crush to black."));
    }
    if (s.gray_bits && s.gray_bits < 13) out.push(F("amber", `Low gray depth (${s.gray_bits}-bit)`, "Expect visible banding in dark scenes."));
    if (s.calibration === false) out.push(F("info", "Module calibration switched off", "Colour can look uneven between modules. A calibration service is possible."));
    const b = s.brightness_pct;
    if (b != null && b < 50) out.push(F("amber", `Brightness saved at ${b}%`, "The wall will run dim with this file. Fine for a dark room, otherwise raise it."));
    if (OLD.some((c) => (s.driver_chip || "").toUpperCase().startsWith(c))) out.push(F("info", `Older driver chip (${s.driver_chip})`, "Likely to flicker on phone cameras. Good candidate for an upgrade pitch."));
    if (s.refresh_hz && s.refresh_hz < 1920 && !s.refresh_note) out.push(F("amber", `Low refresh (${s.refresh_hz} Hz)`, "May show lines or flicker on camera."));
    const sw = s.software || "";
    if (sw.startsWith("NovaLCT V5.4") || sw.startsWith("NovaLCT V5.3")) out.push(F("info", `Saved with an older NovaLCT (${sw})`, "Fine to use; newer cards may need a re-save."));
    return out;
  }
  const worst = (f) => { const l = new Set(f.map((x) => x.level)); return l.has("red") ? "red" : l.has("amber") ? "amber" : l.has("info") ? "info" : "ok"; };

  function layout(root, rc) {
    const g = (p) => gx(root, p);
    const groups = int(g("StandardLedModuleProp/DataGroup")) || 1;
    const recs = new Map((rc ? rc.records : []).map((r) => [r.addr, r.data]));
    const scan = int(g("StandardLedModuleProp/ScanType").replace("Scan_", "")) || null;
    const order = scan && recs.has(0x1c000100) ? [...recs.get(0x1c000100)].slice(0, scan) : [];
    const gt = recs.get(0x05000000);
    return {
      brand: "NovaStar", source: "file",
      module_cols: int(g("StandardLedModuleProp/ModulePixelCols")), module_rows: int(g("StandardLedModuleProp/ModulePixelRows")),
      scan, data_groups_per_module: groups,
      rows_per_group: b64bytes(g("StandardLedModuleProp/RowsCtrlByDataGroup")).filter((v) => v).slice(0, groups),
      group_start_rows: b64bytes(g("StandardLedModuleProp/StartPositionOfDataGroup")).slice(0, groups),
      data_direction: g("StandardLedModuleProp/DataDirectType"),
      modules_across: int(g("ModuleCols")), modules_down: int(g("ModuleRows")), cascade: g("ModCascadeType"),
      scan_line_order: order.length ? order : scan ? [...Array(scan).keys()] : [],
      scan_order_source: order.length ? "file" : "standard",
      gamma_table_256: gt ? u16s(gt) : [], gray_bits: int(g("GrayDepth")), brightness_0_255: int(g("Brightness")),
      irregular: g("IsIrRegular") === "true",
    };
  }
  const WALK = new Set(["StandardLedModuleProp", "DriverChipType", "CabinetInfo", "ConfigFileVersion", "HWProgramVersionList",
    "ScanBoardVersionInfo", "ChipPropey", "RedProperty", "GreenProperty", "BlueProperty"]);
  async function flatFields(root) {
    const out = {};
    async function walk(e, pre) {
      for (const c of e.children) {
        const p = pre + c.tagName;
        if (!c.children.length) {
          const t = c.textContent.trim();
          out[p] =t.length <= 80 ? t : `<table ${t.length} chars, #${hex(await crypto.subtle.digest("SHA-1", te.encode(t))).slice(0, 6)}>`;
        } else if (WALK.has(c.tagName)) await walk(c, p + "/");
      }
    }
    await walk(root, "");
    return out;
  }

  async function inspectNova(file, chips) {
    const buf = await file.arrayBuffer();
    const entries = await unzip(buf);
    const xmlE = entries.find((e) => /\.xml$/i.test(e.name)), binE = entries.find((e) => /\.bin$/i.test(e.name));
    if (!xmlE) throw new Error("no settings (XML) inside this .rcfgx");
    const problems = [];
    let rc = null;
    if (binE) { try { rc = parseRCCB(binE.bytes); } catch (e) { problems.push(`card instructions unreadable: ${e.message}`); } }
    else problems.push("card instructions (.bin) missing");
    const doc = new DOMParser().parseFromString(td.decode(xmlE.bytes).replace(/^﻿/, ""), "application/xml");
    if (doc.getElementsByTagName("parsererror").length) throw new Error("settings XML is damaged");
    const root = doc.documentElement;
    const s = spec(root, rc, file.name, chips);
    const findings = checks(s, problems);
    const fields = await flatFields(root);
    if (rc) fields["(card instructions) records"] = String(rc.records.length);
    // same id as the desktop library: sha1 of zip members ordered by extension
    const sorted = [...entries].sort((a, b) => (a.name.split(".").pop() > b.name.split(".").pop() ? 1 : -1));
    const all = new Uint8Array(sorted.reduce((n, e) => n + e.bytes.length, 0));
    let o = 0; for (const e of sorted) { all.set(e.bytes, o); o += e.bytes.length; }
    const id = hex(await crypto.subtle.digest("SHA-1", all)).slice(0, 12);
    return { id, brand: "NovaStar", spec: s, findings, level: worst(findings), layout: layout(root, rc), fields };
  }

  return { decrypt, inspectNova };
})();
