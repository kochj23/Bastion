# Bastion AI Attack Methods - Fix Summary

**Date:** January 20, 2026
**Issue:** AI attack methods were not working

## Root Causes Identified

### 1. **Wrong Default Model** (CRITICAL)
- **Problem:** App defaulted to "llama2" model which wasn't installed
- **Impact:** Ollama requests failed silently, activeBackend stayed nil
- **Fix:** Changed default from "llama2" to "mistral:latest"
- **Files Modified:**
  - `Bastion/AI/AIBackendManager.swift` (lines 73, 112)

### 2. **Missing Auto-Selection Logic**
- **Problem:** If saved model didn't exist, app wouldn't auto-select an available model
- **Impact:** Backend stayed in failed state even with Ollama running
- **Fix:** Added logic to auto-select first available model
- **Files Modified:**
  - `Bastion/AI/AIBackendManager.swift` (lines 193-198)

### 3. **AI Methods Never Called From UI** (CRITICAL)
- **Problem:** AI attack orchestration methods existed but were never integrated into the UI workflow
- **Impact:** No matter what the user clicked, AI features never ran
- **Methods Not Being Called:**
  - `AIAttackOrchestrator.orchestrateAttacks()`
  - `AIAttackOrchestrator.selectExploits()`
  - `AIExploitGenerator.generateExploit()`

### 4. **Simulated AI Response in UI**
- **Problem:** "Ask AI" feature in AIInsightsView just returned fake responses
- **Impact:** Users thought AI wasn't working when it was just not connected
- **Fix:** Replaced simulation with actual AIBackendManager.generate() call
- **Files Modified:**
  - `Bastion/Views/AIInsightsView.swift` (lines 221-251)

### 5. **Empty Attack Button Actions**
- **Problem:** "AI-Recommended Attack Plan" button had empty action (just `// Launch attack` comment)
- **Impact:** Clicking the button did absolutely nothing
- **Fix:** Implemented full AI attack workflow
- **Files Modified:**
  - `Bastion/Views/DeviceDetailView.swift` (lines 614-686)

## What Now Works

### ✅ AI Backend Detection
- App correctly detects Ollama is running
- Auto-selects available model if saved model doesn't exist
- Shows green indicator when AI backend is active

### ✅ AI Insights "Ask AI" Feature
- Actually calls Ollama/MLX/TinyLLM
- Returns real AI-generated security advice
- Shows clear error if backend not available

### ✅ AI-Recommended Attack Plan Button
- Calls `aiOrchestrator.selectExploits()` with device context
- Shows AI analysis with success probabilities
- Displays results in formatted card

## How to Test

### 1. Verify AI Backend is Connected
```bash
# Open Bastion app
# Go to Settings → AI Backends
# You should see:
#   - Active: Ollama
#   - Ollama: Available
#   - Selected Model: mistral:latest (or first available)
```

### 2. Test "Ask AI" Feature
```
# In Bastion app:
# 1. Click "AI Insights" tab
# 2. Type question: "What's the most dangerous vulnerability?"
# 3. Click "Ask AI"
# 4. Should get real AI response (not simulation)
```

### 3. Test AI Attack Recommendations
```
# In Bastion app:
# 1. Scan network to find devices
# 2. Click on a device to open detail view
# 3. Go to "Attack Options" tab
# 4. Click "AI-Recommended Attack Plan"
# 5. Should see AI analysis with recommendations
```

## Technical Details

### AI Orchestration Flow
1. User clicks "AI-Recommended Attack Plan"
2. `DeviceDetailView.runAIAttack()` is called
3. Checks if `AIBackendManager.shared.activeBackend != nil`
4. Extracts CVEs from device vulnerabilities
5. Calls `aiOrchestrator.selectExploits(device, cves)`
6. AI analyzes device and generates recommendations
7. Results displayed in formatted card

### AI Backend Selection Priority (Auto Mode)
1. **Ollama** (preferred) - localhost:11434
2. **TinyLLM** (fallback) - localhost:8000
3. **MLX** (last resort) - Python + mlx-lm

## Files Modified

1. `Bastion/AI/AIBackendManager.swift`
   - Default model: "llama2" → "mistral:latest"
   - Added auto-selection of first available model

2. `Bastion/Views/AIInsightsView.swift`
   - Replaced simulated askAI() with real AI calls

3. `Bastion/Views/DeviceDetailView.swift`
   - Added @EnvironmentObject for aiOrchestrator and cveDatabase
   - Added isRunningAIAttack state
   - Implemented runAIAttack() function
   - Added aiResultsCard view
   - Made attack buttons actually call AI methods

## Verification

### Before Fix
```
✗ activeBackend = nil (Ollama not detected)
✗ AI methods never called from UI
✗ "Ask AI" returned fake responses
✗ Attack buttons did nothing
```

### After Fix
```
✓ activeBackend = .ollama
✓ Model: mistral:latest
✓ AI methods integrated into UI workflow
✓ "Ask AI" calls real AI backend
✓ Attack buttons trigger AI analysis
```

## Next Steps (Optional Enhancements)

1. **Implement Other Attack Buttons**
   - Default Credentials Test
   - CVE Exploit attempts
   - Web Application Scan
   - Brute Force Attack

2. **Add Progress Indicators**
   - Show spinner while AI is analyzing
   - Display token count or response time

3. **Persist AI Recommendations**
   - Save AI results to attack history
   - Export AI reports to PDF

4. **Network-Wide AI Orchestration**
   - Implement `orchestrateAttacks()` for entire network
   - Show attack chains and pivot opportunities

---

**Built by Jordan Koch**
**Date:** January 20, 2026
