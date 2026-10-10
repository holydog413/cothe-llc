/* COTHE LLC quote builder. Edit prices here. */
var COTHE_PRICES = {
  tiers: [
    { id: "home",   name: "Home Security Check",                 price: 249,  kind: "home",     retest: true },
    { id: "remote", name: "Remote external-only check",          price: 129,  kind: "home",     retest: true },
    { id: "smb",    name: "Small Business (up to 10 devices, 1 site)", price: 895, kind: "business", retest: true },
    { id: "smbp",   name: "Small Business Plus (11–25 devices)", price: 1495, kind: "business", retest: true }
  ],
  extraDevice: 35,            // each, one-time
  extraSite: 295,             // each, one-time
  retestPct: 0.35,            // of selected base tier
  remediationHr: 95,
  afterHoursHr: 125,
  monitorHome: 19,            // per month
  monitorBizBase: 99,         // per month
  monitorBizPerDevice: 8,     // per device per month
  discountPct: 0.10           // veteran / first responder, one-time services only
};

(function () {
  var P = COTHE_PRICES, T = window.COTHE_TAX || {};
  var $ = function (id) { return document.getElementById(id); };
  var money = function (n) { return "$" + n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }); };
  var whole = function (n) { return "$" + n.toLocaleString("en-US"); };
  $("yr").textContent = new Date().getFullYear();

  $("tiers").innerHTML = P.tiers.map(function (t, i) {
    return '<div class="q-row"><label><input type="radio" name="tier" value="' + t.id + '"' + (i === 0 ? " checked" : "") +
      " /> " + t.name + '</label><span class="q-price">' + whole(t.price) + "</span></div>";
  }).join("") + '<div class="q-row"><label><input type="radio" name="tier" value="none" /> No assessment (add-ons / help only)</label></div>';

  $("addons").innerHTML =
    row("qDev", "Extra device", whole(P.extraDevice) + " each") +
    row("qSite", "Extra site", whole(P.extraSite) + " each") +
    '<div class="q-row"><label><input type="checkbox" id="retest" /> Re-test after fixes <small>35% of selected base tier (≈ Home $89, SMB $295)</small></label><span class="q-price" id="retestPrice"></span></div>' +
    row("qRem", "Remediation help (hours)", whole(P.remediationHr) + "/hr") +
    row("qAfter", "After-hours remediation (hours)", whole(P.afterHoursHr) + "/hr");

  $("monitoring").innerHTML =
    '<div class="q-row"><label><input type="radio" name="mon" value="none" checked /> None</label></div>' +
    '<div class="q-row"><label><input type="radio" name="mon" value="home" /> Home monitoring</label><span class="q-price">' + whole(P.monitorHome) + "/mo</span></div>" +
    '<div class="q-row"><label><input type="radio" name="mon" value="biz" /> Business monitoring <small>' + whole(P.monitorBizBase) + "/mo + " + whole(P.monitorBizPerDevice) + "/device/mo</small></label>" +
    '<input type="number" id="qMonDev" min="0" value="10" aria-label="Monitored devices" /></div>';

  function row(id, label, price) {
    return '<div class="q-row"><label for="' + id + '">' + label + " <small>" + price + "</small></label>" +
      '<input type="number" id="' + id + '" min="0" step="1" value="0" inputmode="numeric" /></div>';
  }

  var sel = $("state");
  sel.innerHTML = '<option value="">— Select state —</option>' + Object.keys(T).sort(function (a, b) {
    return T[a].name.localeCompare(T[b].name);
  }).map(function (k) { return '<option value="' + k + '">' + T[k].name + "</option>"; }).join("");
  sel.value = "OH";

  function num(id) { var v = parseFloat($(id).value); return isFinite(v) && v > 0 ? v : 0; }
  function radio(n) { var r = document.querySelector('input[name="' + n + '"]:checked'); return r ? r.value : ""; }

  function taxableFlag(flag, use) {
    return flag === "Y" || (flag === "B" && use === "business") || (flag === "P" && use === "personal");
  }

  var last = null;
  function calc() {
    var tier = P.tiers.filter(function (t) { return t.id === radio("tier"); })[0];
    var lines = []; // {desc, amt, cat}
    if (tier) lines.push({ desc: tier.name, amt: tier.price, cat: "assess" });
    var d = Math.round(num("qDev")), s = Math.round(num("qSite")), r = num("qRem"), ah = num("qAfter");
    if (d) lines.push({ desc: "Extra device × " + d, amt: d * P.extraDevice, cat: "assess" });
    if (s) lines.push({ desc: "Extra site × " + s, amt: s * P.extraSite, cat: "assess" });
    var rt = tier ? Math.round(tier.price * P.retestPct * 100) / 100 : 0;
    $("retestPrice").textContent = tier ? money(rt) : "—";
    $("retest").disabled = !tier;
    if (tier && $("retest").checked) lines.push({ desc: "Re-test after fixes (35%)", amt: rt, cat: "assess" });
    if (r) lines.push({ desc: "Remediation help × " + r + " hr", amt: r * P.remediationHr, cat: "labor" });
    if (ah) lines.push({ desc: "After-hours remediation × " + ah + " hr", amt: ah * P.afterHoursHr, cat: "labor" });

    var mon = radio("mon"), monDev = Math.round(num("qMonDev")), monthly = 0, monDesc = "";
    if (mon === "home") { monthly = P.monitorHome; monDesc = "Home monitoring"; }
    if (mon === "biz") { monthly = P.monitorBizBase + monDev * P.monitorBizPerDevice; monDesc = "Business monitoring (" + monDev + " devices)"; }

    var st = T[sel.value], use = radio("use"), local = num("localRate");
    var disc = $("discount").checked ? P.discountPct : 0;
    var subtotal = 0, taxable = 0;
    lines.forEach(function (l) {
      subtotal += l.amt;
      if (st && taxableFlag(st[l.cat], use)) taxable += l.amt * (1 - disc) * ((st.pct || 100) / 100);
    });
    var discount = Math.round(subtotal * disc * 100) / 100;
    var rate = st ? ((st.effRate != null ? st.effRate : st.rate) + local) : 0;
    taxable = Math.round(taxable * 100) / 100;
    var tax = Math.round(taxable * rate) / 100;
    var oneTime = subtotal - discount + tax;
    var monTaxable = st && monthly && taxableFlag(st.monitor, use) ? Math.round(monthly * ((st.pct || 100) / 100) * 100) / 100 : 0;
    var monTax = Math.round(monTaxable * rate) / 100;

    $("lines").innerHTML = lines.length ? '<table class="q-sum">' + lines.map(function (l) {
      var tx = st && taxableFlag(st[l.cat], use);
      return "<tr><td>" + l.desc + (tx ? '<span class="q-tag">TAX</span>' : "") + "</td><td>" + money(l.amt) + "</td></tr>";
    }).join("") + "</table>" : '<p class="muted">No one-time services selected.</p>';

    $("sum").innerHTML =
      "<tr><td>Subtotal</td><td>" + money(subtotal) + "</td></tr>" +
      (discount ? "<tr><td>Veteran / first responder discount (10%)</td><td>−" + money(discount) + "</td></tr>" : "") +
      '<tr class="sub"><td>Taxable amount' + (st && st.pct ? " (" + st.pct + "% of taxable charges)" : "") + "</td><td>" + money(taxable) + "</td></tr>" +
      "<tr><td>Est. tax (" + rate.toFixed(3).replace(/\.?0+$/, "") + "%)</td><td>" + money(tax) + "</td></tr>" +
      '<tr class="total"><td>One-time total</td><td>' + money(oneTime) + "</td></tr>" +
      (monthly ? "<tr><td style='padding-top:1rem'>" + monDesc + "</td><td style='padding-top:1rem'>" + money(monthly) + "/mo</td></tr>" +
        "<tr><td>Est. monthly tax</td><td>" + money(monTax) + "/mo</td></tr>" +
        '<tr class="total"><td>Monthly recurring</td><td>' + money(monthly + monTax) + "/mo</td></tr>" : "");

    var note = st ? "<strong>" + st.name + ":</strong> " + st.note +
      (st.effRate != null ? " Special rate " + st.effRate + "% used." : " State base rate " + st.rate + "%.") +
      (local ? " Plus local " + local + "%." : " Local/county rates may add.") : "Select your state to estimate tax.";
    if (sel.value === "OH") note += " Ohio: taxable for <em>business</em> use, not for personal/home use (current selection: " + use + ").";
    $("taxnote").innerHTML = note;

    last = {
      tier: tier ? tier.name : "None", lines: lines.map(function (l) { return l.desc + ": " + money(l.amt); }),
      state: st ? st.name : "(not selected)", use: use, localRate: local, discount: !!disc,
      subtotal: subtotal, discountAmt: discount, taxable: taxable, taxRate: rate, tax: tax, oneTimeTotal: oneTime,
      monitoring: monthly ? monDesc : "None", monthly: monthly, monthlyTax: monTax, monthlyTotal: monthly + monTax,
      createdAt: new Date().toISOString()
    };
    try { localStorage.setItem("cothe_quote", JSON.stringify(last)); } catch (e) {}
  }

  function text(q) {
    return [
      "COTHE LLC estimate (" + q.createdAt.slice(0, 10) + ")",
      q.lines.join("\n") || "(no one-time services)",
      "Subtotal " + money(q.subtotal) + (q.discount ? " | Discount −" + money(q.discountAmt) : ""),
      "Taxable " + money(q.taxable) + " | Tax " + money(q.tax) + " (" + q.taxRate + "%, " + q.state + ", " + q.use + ")",
      "One-time total " + money(q.oneTimeTotal),
      q.monthly ? q.monitoring + ": " + money(q.monthly) + "/mo + tax " + money(q.monthlyTax) + " = " + money(q.monthlyTotal) + "/mo" : "Monitoring: none",
      "Estimate only; final tax on invoice."
    ].join("\n");
  }
  window.COTHE_QUOTE_TEXT = text;

  document.querySelector("main").addEventListener("input", calc);
  document.querySelector("main").addEventListener("change", calc);
  $("copyQ").addEventListener("click", function () {
    var t = text(last);
    if (navigator.clipboard) navigator.clipboard.writeText(t).then(function () { $("copyQ").textContent = "Copied!"; });
    else prompt("Copy your quote:", t);
  });
  calc();
})();
