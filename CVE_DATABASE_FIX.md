# CVE Database - UI Improvements & Download Guide

**Date:** January 20, 2026
**Issue:** CVE Database card showed "Not Downloaded" with no clear action

## What Was Improved

### ✅ Before:
- Static card showing "Not Downloaded"
- No visual indication of what to do
- Users confused about how to download
- Had to manually navigate to Settings

### ✅ After:
- **Clickable card** - Tapping opens Settings automatically
- Shows "**Tap to Download**" with download icon (⬇️)
- Color-coded:
  - 🟢 Green (statusLow) when database loaded
  - 🟠 Orange (statusHigh) when not downloaded
- Tooltip explains: "Click to download CVE database (~2GB, 10-20 min)"
- Checkmark icon (✓) when database is loaded

### Code Changes

**File:** `DashboardView.swift`

**Before:**
```swift
StatCard(
    title: "CVE Database",
    value: cveDatabase.totalCVEs > 0 ? "\(cveDatabase.totalCVEs / 1000)k" : "Not Downloaded",
    icon: "doc.text.fill",
    color: ModernColors.accent
)
```

**After:**
```swift
Button {
    showSettings = true  // Opens Settings sheet
} label: {
    StatCard(
        title: "CVE Database",
        value: cveDatabase.totalCVEs > 0 ? "\(cveDatabase.totalCVEs / 1000)k CVEs" : "Tap to Download",
        icon: cveDatabase.totalCVEs > 0 ? "checkmark.circle.fill" : "arrow.down.circle.fill",
        color: cveDatabase.totalCVEs > 0 ? ModernColors.statusLow : ModernColors.statusHigh
    )
}
.buttonStyle(.plain)
.help(cveDatabase.totalCVEs > 0 ? "CVE database loaded" : "Click to download CVE database (~2GB, 10-20 min)")
```

## How to Download CVE Database

### Method 1: Click the Dashboard Card (NEW!)
1. **Open Bastion app**
2. **Click the "CVE Database" card** on dashboard (shows "Tap to Download")
3. **Settings opens** automatically
4. **Click "CVE Database" tab**
5. **Click "Download CVE Database (~2GB)"** button
6. **Wait 10-20 minutes** for download to complete

### Method 2: Manual Navigation (Old Way)
1. Open Bastion app
2. Click Settings button (gear icon)
3. Go to "CVE Database" tab
4. Click "Download CVE Database (~2GB)"

### Download Details
- **Size:** ~2GB compressed
- **Time:** 10-20 minutes (depends on internet speed)
- **Years:** 2002 - Present (downloads all years)
- **Source:** NIST NVD (National Vulnerability Database)
- **Format:** JSON files, one per year
- **Location:** `~/Library/Application Support/Bastion/CVE/`

## Known Issue: NVD API Deprecation ⚠️

### The Problem
The CVE download uses the **NVD API 1.1** which was **deprecated in 2021** and replaced with **API 2.0**.

**Old API (what Bastion uses):**
```swift
"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-\(year).json.gz"
```

**New API (requires API key):**
```
https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=...&apiKey=YOUR_KEY
```

### Impact
- Old API feeds may be unavailable
- Download might fail with 404 errors
- Need to migrate to API 2.0

### Temporary Solution
If the NVD download fails:

1. **Use Manual CVE Data:**
   - Download from: https://github.com/CVEProject/cvelistV5
   - Place JSON files in: `~/Library/Application Support/Bastion/CVE/`

2. **Alternative CVE Sources:**
   - Vulners API: https://vulners.com/api/v3/
   - CVE.org API: https://www.cve.org/AllResources/CveServices
   - Exploit-DB: https://www.exploit-db.com/

### Long-Term Fix (TODO)
Migrate to NVD API 2.0:

```swift
// Required changes to CVEDatabase.swift
1. Get free API key from: https://nvd.nist.gov/developers/request-an-api-key
2. Update URL to use API 2.0 endpoint
3. Add API key to secure storage (Keychain)
4. Handle pagination (API 2.0 returns 2000 CVEs max per request)
5. Update JSON parsing for new format
```

**Files to modify:**
- `Bastion/Security/CVEDatabase.swift` (lines 56-83)
- Add API key settings to `SettingsView.swift`

## Testing the Fix

### Verify CVE Card is Clickable
1. **Launch Bastion**
2. **Dashboard shows CVE Database card**
3. **Card shows:** "Tap to Download" with orange color
4. **Hover over card:** Tooltip appears
5. **Click card:** Settings sheet opens

### Verify Download Button
1. **In Settings → CVE Database tab**
2. **Button shows:** "Download CVE Database (~2GB)"
3. **Click button:** Download starts
4. **Progress bar shows:** 0% → 100%
5. **Card updates:** Shows CVE count when complete

### Verify Success State
Once downloaded:
- ✅ Card shows: "250k CVEs" (example count)
- ✅ Color changes to green
- ✅ Icon changes to checkmark (✓)
- ✅ Tooltip: "CVE database loaded"

## What This Enables

Once CVE database is downloaded, Bastion can:

1. **Match CVEs to Services**
   - Detects SSH 7.4 → Shows CVE-2018-15473 (username enumeration)
   - Detects Apache 2.4.29 → Shows CVE-2017-15715 (file upload)

2. **AI-Powered Exploit Selection**
   - AI reads CVE descriptions
   - Recommends which CVEs to exploit
   - Generates custom exploits

3. **Vulnerability Scoring**
   - CVSS scores (0-10)
   - Severity levels (Low/Medium/High/Critical)
   - Risk assessment

4. **CVE Search**
   - Search by CVE ID (CVE-2021-44228)
   - Search by keyword ("OpenSSL")
   - Search by severity

## Alternative: Bundled CVE Database (Future)

### Option 1: Include in App Bundle
- Pre-download top 10,000 critical CVEs
- Bundle with app (~50MB compressed)
- Auto-updates on launch

### Option 2: Cloud-Hosted CVE API
- Host CVE database on cloud server
- App fetches CVEs via REST API
- No local download required

### Option 3: Hybrid Approach
- Bundle critical CVEs (top 10k)
- Download full database optionally
- Use cloud API for latest CVEs

## Summary

### What Works Now ✅
- CVE Database card is clickable
- Opens Settings automatically
- Clear visual indicators
- Helpful tooltips
- Color-coded status

### What Might Not Work ⚠️
- NVD API 1.1 download (deprecated)
- May need migration to API 2.0
- Alternative CVE sources recommended

### User Experience Improvements
- **Before:** "Not Downloaded" (confusing)
- **After:** "Tap to Download" (actionable)
- **Before:** No indication of what to do
- **After:** Click card → Settings opens → Download button
- **Before:** Static card
- **After:** Interactive with tooltips

---

**Built by Jordan Koch**
**Date:** January 20, 2026

## Quick Test Commands

```bash
# Check if CVE database exists
ls -lh ~/Library/Application\ Support/Bastion/CVE/

# Check CVE file sizes
du -sh ~/Library/Application\ Support/Bastion/CVE/*

# Test NVD API availability
curl -I "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz"

# If you get 404, API is deprecated. Need to migrate to 2.0.
```
