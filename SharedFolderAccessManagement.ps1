# ==========================================================
# ENTERPRISE SHARED FOLDER ACCESS MANAGEMENT TOOL
# WITH FULL AUDIT LOGGING
# ==========================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# -------------------------------
# ADMIN CHECK
# -------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [System.Windows.Forms.MessageBox]::Show(
        "Please run this script as Administrator.",
        "Access Denied",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit
}

# -------------------------------
# ACTIVE DIRECTORY CHECK
# -------------------------------
if (-not (Get-Module -ListAvailable ActiveDirectory)) {
    [System.Windows.Forms.MessageBox]::Show(
        "ActiveDirectory module not found.`nInstall RSAT and try again.",
        "Missing Dependency",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit
}

Import-Module ActiveDirectory

# -------------------------------
# LOGGING SETUP
# -------------------------------
$LogDir  = "C:\logs"
$LogFile = "$LogDir\SharedFolderAccess_Audit.csv"

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

if (-not (Test-Path $LogFile)) {
    "Timestamp,SessionId,ExecutedBy,ComputerName,Action,FolderPath,User,Permission,Method,Result,Message" |
        Out-File $LogFile -Encoding UTF8
}

$SessionId   = [guid]::NewGuid().ToString()
$ExecutedBy  = "$env:USERDOMAIN\$env:USERNAME"
$Computer    = $env:COMPUTERNAME

function Escape-Csv {
    param($Value)
    if ($null -eq $Value) { return "" }
    '"' + ($Value -replace '"','""') + '"'
}

function Write-AuditLog {
    param(
        $Action,
        $FolderPath,
        $User,
        $Permission,
        $Method,
        $Result,
        $Message
    )

    $line = @(
        Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $SessionId
        $ExecutedBy
        $Computer
        $Action
        $FolderPath
        $User
        $Permission
        $Method
        $Result
        $Message
    ) | ForEach-Object { Escape-Csv $_ }

    ($line -join ",") | Out-File $LogFile -Append -Encoding UTF8
}


# -------------------------------
# HELPER FUNCTIONS
# -------------------------------
function Get-NtfsRight {
    param($Permission)
    switch ($Permission) {
        "Read"        { "ReadAndExecute" }
        "Modify"      { "Modify" }
        "FullControl" { "FullControl" }
    }
}

function Get-ExistingGroupRule {
    param($Acl, $NtfsRight)

    $Acl.Access | Where-Object {
        $_.AccessControlType -eq "Allow" -and
        $_.IdentityReference.Value -match "\\" -and
        $_.IdentityReference.Value -notmatch "BUILTIN|NT AUTHORITY" -and
        ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::$NtfsRight)
    } | Select-Object -First 1
}

function Validate-ADUser {
    param($User)
    try {
        Get-ADUser $User -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

# -------------------------------
# UI FORM
# -------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "Enterprise Shared Folder Access Manager"
$form.Size = New-Object System.Drawing.Size(560,480)
$form.StartPosition = "CenterScreen"
$form.Font = New-Object System.Drawing.Font("Segoe UI",10)

# -------------------------------
# GROUP BOX
# -------------------------------
$group = New-Object System.Windows.Forms.GroupBox
$group.Text = "Access Details"
$group.Size = New-Object System.Drawing.Size(520,310)
$group.Location = New-Object System.Drawing.Point(15,15)
$form.Controls.Add($group)

# Folder Path
$lblFolder = New-Object System.Windows.Forms.Label
$lblFolder.Text = "Shared Folder Path"
$lblFolder.Location = New-Object System.Drawing.Point(20,30)
$group.Controls.Add($lblFolder)

$txtFolder = New-Object System.Windows.Forms.TextBox
$txtFolder.Size = New-Object System.Drawing.Size(470,25)
$txtFolder.Location = New-Object System.Drawing.Point(20,55)
$group.Controls.Add($txtFolder)

# Users
$lblUsers = New-Object System.Windows.Forms.Label
$lblUsers.Text = "Users (DOMAIN\User1;DOMAIN\User2)"
$lblUsers.Location = New-Object System.Drawing.Point(20,90)
$group.Controls.Add($lblUsers)

$txtUsers = New-Object System.Windows.Forms.TextBox
$txtUsers.Size = New-Object System.Drawing.Size(470,25)
$txtUsers.Location = New-Object System.Drawing.Point(20,115)
$group.Controls.Add($txtUsers)

# Action
$lblAction = New-Object System.Windows.Forms.Label
$lblAction.Text = "Action"
$lblAction.Location = New-Object System.Drawing.Point(20,150)
$group.Controls.Add($lblAction)

$comboAction = New-Object System.Windows.Forms.ComboBox
$comboAction.Items.AddRange(@("Add Access","Remove Access"))
$comboAction.DropDownStyle = "DropDownList"
$comboAction.Location = New-Object System.Drawing.Point(20,175)
$comboAction.Width = 220
$group.Controls.Add($comboAction)

# Permission
$lblPerm = New-Object System.Windows.Forms.Label
$lblPerm.Text = "Permission Level"
$lblPerm.Location = New-Object System.Drawing.Point(270,150)
$group.Controls.Add($lblPerm)

$comboPerm = New-Object System.Windows.Forms.ComboBox
$comboPerm.Items.AddRange(@("Read","Modify","FullControl"))
$comboPerm.DropDownStyle = "DropDownList"
$comboPerm.Location = New-Object System.Drawing.Point(270,175)
$comboPerm.Width = 220
$group.Controls.Add($comboPerm)

# Status
$status = New-Object System.Windows.Forms.Label
$status.Location = New-Object System.Drawing.Point(20,340)
$status.Size = New-Object System.Drawing.Size(520,50)
$form.Controls.Add($status)

# Button
$btnExecute = New-Object System.Windows.Forms.Button
$btnExecute.Text = "Execute"
$btnExecute.Size = New-Object System.Drawing.Size(140,38)
$btnExecute.Location = New-Object System.Drawing.Point(200,400)
$btnExecute.BackColor = [System.Drawing.Color]::SteelBlue
$btnExecute.ForeColor = [System.Drawing.Color]::White
$form.Controls.Add($btnExecute)

# -------------------------------
# BUTTON CLICK LOGIC
# -------------------------------
$btnExecute.Add_Click({

    $btnExecute.Enabled = $false
    $status.Text = ""

    $folderPath = $txtFolder.Text.Trim()
    $usersInput = $txtUsers.Text.Trim()
    $action     = $comboAction.SelectedItem
    $permission = $comboPerm.SelectedItem

    if (-not (Test-Path $folderPath)) {
        $status.ForeColor = "Red"
        $status.Text = "Invalid folder path."
        Write-AuditLog "VALIDATION" $folderPath "" "" "" "FAILED" "Invalid folder path"
        $btnExecute.Enabled = $true
        return
    }

    if (-not $usersInput -or -not $action -or -not $permission) {
        $status.ForeColor = "Red"
        $status.Text = "All fields are required."
        Write-AuditLog "VALIDATION" $folderPath "" "" "" "FAILED" "Missing required fields"
        $btnExecute.Enabled = $true
        return
    }

    $users = $usersInput -split ";" | ForEach-Object { $_.Trim() }
    $ntfsRight = Get-NtfsRight $permission
    $acl = Get-Acl $folderPath
    $groupRule = Get-ExistingGroupRule -Acl $acl -NtfsRight $ntfsRight

    foreach ($user in $users) {

        if (-not (Validate-ADUser $user)) {
            $status.ForeColor = "Red"
            $status.Text = "Invalid AD user: $user"
            Write-AuditLog $action $folderPath $user $permission "" "FAILED" "Invalid AD user"
            $btnExecute.Enabled = $true
            return
        }

        if ($groupRule) {
            $groupName = ($groupRule.IdentityReference.Value -split "\\")[1]

            try {
                if ($action -eq "Add Access") {
                    Add-ADGroupMember -Identity $groupName -Members $user -ErrorAction Stop
                } else {
                    Remove-ADGroupMember -Identity $groupName -Members $user -Confirm:$false -ErrorAction Stop
                }

                Write-AuditLog $action $folderPath $user $permission "ADGroup:$groupName" "SUCCESS" "Completed via group"
                $status.ForeColor = "DarkGreen"
                $status.Text = "Processed via AD group: $groupName"
            }
            catch {
                Write-AuditLog $action $folderPath $user $permission "ADGroup:$groupName" "FAILED" $_.Exception.Message
                $status.ForeColor = "Red"
                $status.Text = $_.Exception.Message
            }
        }
        else {
            try {
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $user,
                    $ntfsRight,
                    "ContainerInherit,ObjectInherit",
                    "None",
                    "Allow"
                )

                if ($action -eq "Add Access") {
                    $acl.AddAccessRule($rule)
                }
                else {
                    $acl.Access | Where-Object {
                        $_.IdentityReference.Value -eq $user
                    } | ForEach-Object {
                        $acl.Access | Where-Object {
                        $_.IdentityReference.Value -eq $user -and
                        ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::$ntfsRight)
                        } | ForEach-Object {
                            $acl.RemoveAccessRule($_)
                        }
                    }
                }

                Set-Acl -Path $folderPath -AclObject $acl
                Write-AuditLog $action $folderPath $user $permission "DirectACL" "SUCCESS" "Completed via NTFS"
                $status.ForeColor = "DarkOrange"
                $status.Text = "Processed via direct NTFS permissions."
            }
            catch {
                Write-AuditLog $action $folderPath $user $permission "DirectACL" "FAILED" $_.Exception.Message
                $status.ForeColor = "Red"
                $status.Text = $_.Exception.Message
            }
        }
    }

    $btnExecute.Enabled = $true
})

$form.ShowDialog()