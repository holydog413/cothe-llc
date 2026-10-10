/*
 * COTHE LLC — state sales-tax data for the quote builder (ESTIMATES ONLY — NOT TAX ADVICE).
 * Researched 2026-10-10. Martin: verify with your accountant / the Ohio Dept of Taxation before relying on this.
 *
 * Columns per state:
 *   rate     – STATE base rate % only (local/county/transit rates may add; the page has a "local rate %" field).
 *   assess   – security assessment / IT consulting (Home check, SMB check, re-test, add-ons)
 *   labor    – remediation labor (hourly help, after-hours)
 *   monitor  – monthly monitoring / subscription service
 *     Values: "Y" taxable, "N" not taxable, "B" taxable only when purchased for business use,
 *             "P" taxable only when purchased for personal use.
 *   pct      – % of a taxable charge that is taxed (Texas data processing = 80).
 *   effRate  – optional special rate % that replaces `rate` for these services (CT 1%, MD 3%).
 *   note     – short source note.
 *
 * Main sources:
 *   Rates: Tax Foundation, "2026 Sales Tax Rates, Midyear Update" (no state base-rate changes Jan→Jul 2026)
 *          https://taxfoundation.org/data/all/state/2026-sales-tax-rates-midyear/
 *          DC general rate 6.5% → 7.0% effective 2026-10-01 (sales.tax update, Oct 2026).
 *   Ohio:  ORC 5739.01(B)(3)(e),(Y); OAC 5703-9-46 (eff. 2024-04-15) https://codes.ohio.gov/ohio-administrative-code/rule-5703-9-46
 *          https://tax.ohio.gov/business/sales-and-use-tax/taxability  (ADP / computer services / electronic
 *          information services taxable "for use in business"; personal use not taxable). NOTE: Ohio treats
 *          consulting where the "true object" is a professional service as NOT taxable — COTHE models Ohio
 *          conservatively as taxable for business use per the owner's instruction. Confirm with accountant.
 *   Texas: Comptroller Pub. 94-127 "Data Processing Services are Taxable" https://comptroller.texas.gov/taxes/publications/94-127.php
 *          (consulting not taxable; data processing taxable on 80% of the charge, Tax Code 151.351).
 *   CT:    DRS PS 2006(8) computer & data processing services incl. consulting; taxed at 1% (CGS 12-408(1)(B)).
 *          https://portal.ct.gov/-/media/DRS/Publications/pubsps/2006/PS068pdf.pdf
 *   MD:    3% tax on NAICS 518/519/5415 tech services effective 2025-07-01 (2025 Budget Reconciliation & Financing Act).
 *   WA:    ESSB 5814 (eff. 2025-10-01) adds IT services/tech support/network & data services to retail sales.
 *   HI, NM, SD: broad taxes on services (HI GET 4% state; NM gross receipts 4.875%; SD 4.2% on most non-professional services).
 *   WV:    services taxed unless professional/exempt; data processing exempt (W. Va. Code 11-15-8, 11-15-9).
 *   Overview: https://sales.tax/expert-articles/services-taxability-across-states-what-b2b-companies-get-wrong/
 *             https://www.agenttax.io/classification
 *   Others: states marked "N" generally do not tax professional/IT services (sale of tangible goods/canned software
 *           only). Treatment of security monitoring vs. "information services" is uncertain in several states —
 *           flagged with "verify" in the note.
 */
window.COTHE_TAX = {
  AL:{name:"Alabama",rate:4,assess:"N",labor:"N",monitor:"N",note:"Services generally not taxed."},
  AK:{name:"Alaska",rate:0,assess:"N",labor:"N",monitor:"N",note:"No state sales tax; some boroughs/cities tax services — use local rate."},
  AZ:{name:"Arizona",rate:5.6,assess:"N",labor:"N",monitor:"N",note:"TPT does not reach professional/IT services."},
  AR:{name:"Arkansas",rate:6.5,assess:"N",labor:"N",monitor:"N",note:"Enumerated services list does not include IT consulting; verify if on-site device repair."},
  CA:{name:"California",rate:7.25,assess:"N",labor:"N",monitor:"N",note:"Services not taxed (7.25% incl. 1% statewide local)."},
  CO:{name:"Colorado",rate:2.9,assess:"N",labor:"N",monitor:"N",note:"Services not taxed; many home-rule local taxes."},
  CT:{name:"Connecticut",rate:6.35,effRate:1,assess:"Y",labor:"Y",monitor:"Y",note:"Computer & data processing services (incl. consulting) taxed at 1% — DRS PS 2006(8)."},
  DE:{name:"Delaware",rate:0,assess:"N",labor:"N",monitor:"N",note:"No sales tax (gross receipts tax is on seller)."},
  DC:{name:"District of Columbia",rate:7,assess:"N",labor:"N",monitor:"Y",note:"Rate 7.0% from 2026-10-01. Data processing/information services taxable; monitoring treated as taxable — verify."},
  FL:{name:"Florida",rate:6,assess:"N",labor:"N",monitor:"N",note:"IT/professional services not taxed (local surtax may apply to taxable sales)."},
  GA:{name:"Georgia",rate:4,assess:"N",labor:"N",monitor:"N",note:"Services generally not taxed."},
  HI:{name:"Hawaii",rate:4,assess:"Y",labor:"Y",monitor:"Y",note:"General Excise Tax applies to nearly all services (4% state; county surcharge up to 0.5%; pass-on may be ~4.712%)."},
  ID:{name:"Idaho",rate:6,assess:"N",labor:"N",monitor:"N",note:"Services not taxed."},
  IL:{name:"Illinois",rate:6.25,assess:"N",labor:"N",monitor:"N",note:"Services not taxed (Chicago lease tax on cloud software is local)."},
  IN:{name:"Indiana",rate:7,assess:"N",labor:"N",monitor:"N",note:"Services not taxed."},
  IA:{name:"Iowa",rate:6,assess:"N",labor:"N",monitor:"P",note:"SaaS/specified digital & some info services taxable for personal use; business-use exempt since 2023 — verify monitoring."},
  KS:{name:"Kansas",rate:6.5,assess:"N",labor:"N",monitor:"N",note:"Labor on tangible property taxable; IT consulting not."},
  KY:{name:"Kentucky",rate:6,assess:"N",labor:"N",monitor:"N",note:"2023+ expanded service list; IT consulting not listed — verify (alarm monitoring may be)."},
  LA:{name:"Louisiana",rate:5,assess:"N",labor:"N",monitor:"N",note:"State rate 5% from 2025; 2025 reform added digital products — verify monitoring."},
  ME:{name:"Maine",rate:5.5,assess:"N",labor:"N",monitor:"N",note:"Services generally not taxed."},
  MD:{name:"Maryland",rate:6,effRate:3,assess:"Y",labor:"Y",monitor:"Y",note:"3% tax on IT/computer systems design services (NAICS 5415/518/519) since 2025-07-01."},
  MA:{name:"Massachusetts",rate:6.25,assess:"N",labor:"N",monitor:"N",note:"Services not taxed."},
  MI:{name:"Michigan",rate:6,assess:"N",labor:"N",monitor:"N",note:"Services not taxed."},
  MN:{name:"Minnesota",rate:6.875,assess:"N",labor:"N",monitor:"N",note:"Enumerated services; IT consulting not listed."},
  MS:{name:"Mississippi",rate:7,assess:"N",labor:"Y",monitor:"Y",note:"Computer software services/installation/maintenance taxable; verify classification."},
  MO:{name:"Missouri",rate:4.225,assess:"N",labor:"N",monitor:"N",note:"Services not taxed."},
  MT:{name:"Montana",rate:0,assess:"N",labor:"N",monitor:"N",note:"No general sales tax."},
  NE:{name:"Nebraska",rate:5.5,assess:"N",labor:"N",monitor:"N",note:"Enumerated services; IT consulting not listed — verify software installation."},
  NV:{name:"Nevada",rate:6.85,assess:"N",labor:"N",monitor:"N",note:"Services not taxed."},
  NH:{name:"New Hampshire",rate:0,assess:"N",labor:"N",monitor:"N",note:"No sales tax."},
  NJ:{name:"New Jersey",rate:6.625,assess:"N",labor:"N",monitor:"N",note:"Info services taxable but security assessment/monitoring generally not — verify."},
  NM:{name:"New Mexico",rate:4.875,assess:"Y",labor:"Y",monitor:"Y",note:"Gross receipts tax on services; local GRT adds."},
  NY:{name:"New York",rate:4,assess:"N",labor:"N",monitor:"N",note:"Information & protective services taxable; IT consulting not — verify monitoring."},
  NC:{name:"North Carolina",rate:4.75,assess:"N",labor:"N",monitor:"N",note:"Services not taxed (repair/maintenance of TPP is)."},
  ND:{name:"North Dakota",rate:5,assess:"N",labor:"N",monitor:"N",note:"Services not taxed."},
  OH:{name:"Ohio",rate:5.75,assess:"B",labor:"B",monitor:"B",note:"Computer services / ADP / electronic information services taxable for business use, not personal use — ORC 5739.01(B)(3)(e), OAC 5703-9-46. County + transit rates add (e.g., Franklin 2.25%)."},
  OK:{name:"Oklahoma",rate:4.5,assess:"N",labor:"N",monitor:"N",note:"Services not taxed."},
  OR:{name:"Oregon",rate:0,assess:"N",labor:"N",monitor:"N",note:"No sales tax."},
  PA:{name:"Pennsylvania",rate:6,assess:"N",labor:"N",monitor:"N",note:"Canned software taxable; IT consulting not."},
  RI:{name:"Rhode Island",rate:7,assess:"N",labor:"N",monitor:"N",note:"Limited enumerated services; IT consulting not listed."},
  SC:{name:"South Carolina",rate:6,assess:"N",labor:"N",monitor:"N",note:"Services not taxed."},
  SD:{name:"South Dakota",rate:4.2,assess:"Y",labor:"Y",monitor:"Y",note:"Taxes most services unless specifically exempt; computer services taxable."},
  TN:{name:"Tennessee",rate:7,assess:"N",labor:"Y",monitor:"Y",note:"Computer software installation/repair & remote access software taxable — verify."},
  TX:{name:"Texas",rate:6.25,pct:80,assess:"N",labor:"Y",monitor:"Y",note:"Consulting not taxable; data processing taxable on 80% — Comptroller Pub. 94-127. Remediation as data processing/repair — verify."},
  UT:{name:"Utah",rate:4.85,assess:"N",labor:"N",monitor:"N",note:"Services not taxed."},
  VT:{name:"Vermont",rate:6,assess:"N",labor:"N",monitor:"N",note:"Services not taxed."},
  VA:{name:"Virginia",rate:5.3,assess:"N",labor:"N",monitor:"N",note:"Includes 1% statewide local; services not taxed."},
  WA:{name:"Washington",rate:6.5,assess:"Y",labor:"Y",monitor:"Y",note:"ESSB 5814 (eff. 2025-10-01) taxes IT services, tech support, network/security services."},
  WV:{name:"West Virginia",rate:6,assess:"N",labor:"Y",monitor:"N",note:"Non-professional services taxed; data processing exempt; consulting treated professional — verify."},
  WI:{name:"Wisconsin",rate:5,assess:"N",labor:"N",monitor:"N",note:"Services not taxed."},
  WY:{name:"Wyoming",rate:4,assess:"N",labor:"N",monitor:"N",note:"Services not taxed."}
};
