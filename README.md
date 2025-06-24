# AutoCreateAllowRules.ps1

This PowerShell script dynamically updates Windows Firewall rules based on the latest IP address allocations from the RIPE NCC (Réseaux IP Européens Network Coordination Centre). It focuses on creating allow rules for IPv4 ranges belonging to specific European countries (e.g. DE, FR, BE, LU).

## ✨ Features

- Downloads and parses the latest RIPE NCC IPv4 allocation file.
- Converts address blocks into optimal CIDR notation.
- Automatically creates or replaces inbound Windows Firewall rules for each country.
- Splits large rule sets into manageable batches (if more than 10,000 IPs).
- Logs all operations, including errors and rule creation summaries.

---

## 🛠 Configuration

All configurable values are found at the top of the script:

```powershell
$scriptRoot   = "C:\Path\To\Your\Working\Directory"
$countryCodes = @('DE','FR','BE','LU')  # Customize as needed
$batchSize    = 10000                   # Max CIDRs per firewall rule
```

## 📅 Schedule Execution (Optional)

You can run the script automatically using **Windows Task Scheduler**.  
Follow these steps to schedule it via the GUI:

### 1. Open Task Scheduler
- Press `Windows + R`, type `taskschd.msc`, and press `Enter`.

### 2. Create a New Task
- Click **"Create Task..."** in the right-hand Actions pane.
- Under the **General** tab:
  - Name: `Update Firewall Country Rules`
  - Select **"Run with highest privileges"**
  - Choose **"Configure for:"** your Windows version.

### 3. Set the Trigger
- Go to the **Triggers** tab and click **"New..."**
  - Choose **Daily**, **Weekly**, or as needed.
  - Set the start time.
  - Click **OK**.

### 4. Set the Action
- Go to the **Actions** tab and click **"New..."**
  - Action: **Start a program**
  - Program/script: `powershell.exe`
  - Add arguments:  
    ```
    -ExecutionPolicy Bypass -File "C:\Path\To\Your\Script\AutoCreateAllowRules.ps1"
    ```
  - Click **OK**.

### 5. Save and Test
- Click **OK** to save the task.
- Right-click the task and choose **"Run"** to test.

The script will now run automatically on the schedule you configured.
